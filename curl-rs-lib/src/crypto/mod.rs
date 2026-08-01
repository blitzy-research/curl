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
//! Cryptographic primitives: message digests, keyed digests, randomness.
//!
//! Root of `curl-rs-lib`'s cryptographic primitive layer. This file declares
//! the six primitive modules, re-exports the part of their surface the rest
//! of the crate consumes, and owns the small amount of genuinely shared
//! policy: the lowercase-hex convention, and the two hex-buffer lengths the
//! C tree hard-codes at its call sites.
//!
//! Every claim below carries a `path:line` citation into the C tree or into
//! the workspace manifests, because the behaviour being reproduced is
//! defined by those files and not by this description.
//!
//! # Why this directory exists
//!
//! curl hand-rolled every digest it needed. It had to work with whichever
//! TLS library happened to be linked, and it had to keep working when none
//! was: `lib/md5.c:237-273` and `lib/md4.c:160-196` carry Solar Designer's
//! public-domain reference implementations for exactly that case, and
//! `lib/hmac.c:28-30` guards the whole HMAC unit behind the union of the
//! NTLM, AWS SigV4, Digest and TLS build switches. All of it is replaced
//! here by RustCrypto crates on one `digest` generation (section 4).
//!
//! The consumers inside this crate are:
//!
//! * `auth/` -- HTTP Digest (`md5`, `sha256`, `sha512_256` and their keyed
//!   forms), NTLM (`md4` plus HMAC-MD5), and AWS SigV4 (`sha256` plus
//!   HMAC-SHA256).
//! * `tls/` -- key-log and session-cache identifiers.
//! * `protocols/ws.rs` -- the `Sec-WebSocket-Key` nonce draws on `rand`; its
//!   base64 comes from `util/base64.rs` and never from here.
//! * `cookies/` -- jar and cache identifiers.
//!
//! Nothing here is reachable from outside the crate. No exported libcurl symbol
//! is a hash function, which is why the crate root declares this module
//! `pub(crate)`.
//!
//! # What was superseded, and by what
//!
//! Twelve C files, 3,103 lines, measured with `wc -l`:
//!
//! ```text
//!   C source               lines   paired header          lines
//!   lib/md5.c                609   lib/curl_md5.h            67
//!   lib/md4.c                442   lib/curl_md4.h            37
//!   lib/sha256.c             477   lib/curl_sha256.h         45
//!   lib/curl_sha512_256.c    805   lib/curl_sha512_256.h     43
//!   lib/hmac.c               164   lib/curl_hmac.h           72
//!   lib/rand.c               284   lib/rand.h                58
//!                          -----                          -----
//!                           2781                            322
//! ```
//!
//! 2781 + 322 = 3103. One replacement crate per module:
//!
//! * `md5` -- `md-5 0.10.6`. The crate is published as `md-5`; its library
//!   target is `md5`, so `use md5::Md5` is correct despite the hyphen.
//! * `md4` -- `md4 0.10.2`.
//! * `sha256` -- `sha2 0.10.9`, type `Sha256`.
//! * `sha512_256` -- `sha2 0.10.9`, type `Sha512_256`. SHA-512/256 is
//!   SHA-512 with a truncated initial state, not a variant of SHA-256, and
//!   its block is 128 bytes where SHA-256's is 64: compare
//!   `lib/curl_sha512_256.c:83` (`CURL_SHA512_256_BLOCK_SIZE 128`) with
//!   `lib/sha256.c:468-475` (`Curl_HMAC_SHA256`, 64 and 32). Conflating the
//!   two block sizes silently corrupts every keyed digest, so the two
//!   constants are re-exported here under distinct names.
//! * `hmac` -- `hmac 0.12.1`, generic over the three digests above.
//! * `rand` -- `rand 0.8.7`.
//!
//! # Layering: this directory may use `util`; `util` may never use it
//!
//! The dependency is one-directional. `crypto` may draw on `util` for
//! buffers, base64 and string parsing; `util` must never draw on `crypto`.
//! `util/mod.rs` enforces its side mechanically, and `crypto` is named
//! explicitly in the module list that gate forbids:
//!
//! ```sh
//! grep -rnE 'use crate::(crypto|conn|transfer|protocols|multi)' \
//!   curl-rs-lib/src/util/
//! grep -rnE 'use crate::(easy|tls|dns|auth|proxy|cookies|mime)' \
//!   curl-rs-lib/src/util/
//! grep -rnE 'use crate::(headers|share|url|ffi)' curl-rs-lib/src/util/
//! ```
//!
//! Every one of those must print nothing. Two consequences follow, and both
//! are deliberate:
//!
//! * `util/fopen.rs` needs randomness for its temporary filenames but must
//!   not import `crypto/rand.rs`. It therefore takes randomness by
//!   injection, which is why `rand` exposes an object-safe `Rng` trait
//!   rather than a free function.
//! * `crypto` must not reach for `crate::url` either. Percent-encoding and
//!   hex live on opposite sides of that line, so the `hex_lower` helper at
//!   the foot of this file goes through the `hex` crate and not through
//!   `url/escape.rs`, even though `lib/rand.c:250` routes `Curl_rand_hex`
//!   through `Curl_hexencode` in `lib/escape.c`.
//!
//! # The version pins are load-bearing, not incidental
//!
//! The newest releases of `rand` (0.10.2), `sha2` (0.11.0) and `hmac`
//! (0.13.0) all declare a minimum supported Rust version of 1.85, which the
//! project's floor of 1.75 rules out. The adopted set is pinned exactly, in
//! one place, in the workspace manifest's `[workspace.dependencies]`:
//!
//! ```text
//!   sha1 = "=0.10.7"      md-5 = "=0.10.6"     hmac = "=0.12.1"
//!   sha2 = "=0.10.9"      md4  = "=0.10.2"     des  = "=0.8.1"
//!   rand = "=0.8.7"       hex  = "=0.4.3"
//! ```
//!
//! `curl-rs-lib/Cargo.toml` inherits every one of them with
//! `{ workspace = true }` and restates no version. Do not add a
//! cryptographic dependency here, and do not restate a version in the member
//! manifest. Two independent consequences make the pins load-bearing:
//!
//! * **One `digest` generation.** The latest-version set would put `digest
//!   0.10` and `digest 0.11` in the same graph, and `Hmac<Sha1>` would then
//!   fail to compile, because `Mac` and `Digest` would come from different
//!   crates. That is a build break which only surfaces after the manifests
//!   are written, so it is policed twice: `Cargo.lock:605-606` shows
//!   `digest` present exactly once at 0.10.7, and `deny.toml`'s
//!   `digest:>=0.11.0` entry bans it outright so that a whole-graph
//!   migration to 0.11 -- which would leave no duplicate for that file's
//!   `multiple-versions = "deny"` to catch -- still fails. `hmac.rs` keeps a
//!   `Hmac<Sha1>` assertion in its test module to hold the same guarantee
//!   from the compiler's side.
//! * **`rand` is pinned to match the SSH transport.** `russh` is pinned at
//!   `=0.54.5` in the workspace manifest and its own manifest requires
//!   `rand 0.8`, `digest 0.10`, `hmac 0.12`, `sha1 0.10.5` and `sha2 0.10.6`
//!   (russh-0.54.5 `Cargo.toml:231-232`, `:145-146`, `:182-183`, `:263-264`,
//!   `:267-268`), so `rand 0.8.7` is what this crate resolves to and it
//!   carries `rand_core 0.6.4` across the whole SSH and elliptic-curve
//!   stack. One qualification, stated because measuring the lockfile
//!   contradicts the obvious reading: the pin does **not** unify the graph
//!   outright. `quinn 0.11.9` reaches `quinn-proto 0.11.14`, which requires
//!   `rand 0.9`, so `rand 0.9.5` is present as well. `deny.toml`'s `skip`
//!   list root-causes that and records it as structural -- no admissible
//!   `quinn-proto` version uses `rand 0.8` -- rather than absorbing it
//!   silently. Nothing here may disturb that balance: advancing `rand` in
//!   this directory would break `russh` without healing the split.
//!
//! Nothing in this directory may enable a feature that unions a second
//! cryptographic provider into the graph. The workspace pins `ring`
//! explicitly, with `default-features = false`, on `quinn`, `rustls` and
//! `tokio-rustls`, and `deny.toml` bans `aws-lc-rs` and `aws-lc-sys` by name:
//! that provider vendors C and assembly and needs CMake plus NASM, which
//! breaks the cross-compiled aarch64 Linux leg. `rustls`'s
//! `prefer-post-quantum` feature, which its own default set turns on, is
//! deliberately left out of that explicit list for a related reason: it offers
//! a hybrid key exchange that changes the bytes of the TLS ClientHello, which
//! the byte-exact fixture comparison would reject.
//!
//! # The licence banner is NOT uniform across this directory
//!
//! The banners genuinely differ from one another, each carrying its own C
//! original's attribution. Do not normalise them -- attribution is not
//! boilerplate, and `reuse lint` (`.github/workflows/hygiene.yml:52`) reads
//! what is actually in the file:
//!
//! ```text
//!   file           lines  copyright line(s)                    ident
//!   mod.rs (this)     23  Daniel Stenberg, et al.               L21
//!   md5.rs            23  Daniel Stenberg, et al.               L21
//!   md4.rs            23  Daniel Stenberg, et al.               L21
//!   rand.rs           23  Daniel Stenberg, et al.               L21
//!   sha256.rs         24  Florin Petriuc THEN Daniel Stenberg   L22
//!   sha512_256.rs     23  Evgeny Grin ONLY - no Stenberg line   L21
//!   hmac.rs           25  Daniel Stenberg, plus an RFC 2104     L21
//!                         credit line at lib/hmac.c:23
//! ```
//!
//! Sources: `lib/sha256.c:8-9`, `lib/curl_sha512_256.c:8`,
//! `lib/hmac.c:23`. The same precedent already exists one directory over:
//! `util/inet.rs` alone carries an ISC/BIND banner because its C originals
//! are ISC-licensed, and `util/mod.rs` records that fact so that nobody
//! applies the curl banner across that directory wholesale.
//!
//! Three of the six modules additionally carry an in-body attribution that
//! the licence banner does not cover, and it must travel with the code:
//! `lib/md5.c:237-273` and `lib/md4.c:160-196` (Solar Designer, openwall,
//! placed in the public domain, crediting Colin Plumb),
//! `lib/sha256.c:220` (public domain), and `lib/curl_sha512_256.c:48`,
//! `:161`, `:248` (NetBSD PR 58039 and GNU libmicrohttpd). `lib/hmac.c`
//! and `lib/rand.c` carry none.
//!
//! # What this directory deliberately does not contain
//!
//! Each exclusion below follows from the C tree rather than from preference,
//! and each has a different owner:
//!
//! * **No SHA-1.** curl has no SHA-1 module at all: `ls lib/sha1*` and
//!   `ls lib/curl_sha1*` both find nothing, and `grep -rn 'Curl_sha1' lib/`
//!   is empty. SHA-1 exists only inside the TLS backends. `lib/ws.c` does
//!   not compute it either -- its only mention is the comment at
//!   `lib/ws.c:1359-1363` describing what the *server* does with the
//!   WebSocket GUID; curl's client never verifies `Sec-WebSocket-Accept`.
//!   There is therefore no C source to supersede and no behaviour to
//!   preserve, so inventing one would be a behaviour change. `sha1 0.10.7`
//!   is still a workspace dependency: `hmac.rs` uses it in its test module
//!   for the `Hmac<Sha1>` coherence assertion of section 4, and `russh`
//!   pulls it in transitively. Should a shared SHA-1 wrapper ever be needed,
//!   it belongs in this file -- never as a new module file that the target
//!   layout does not list.
//! * **No DES.** `lib/curl_ntlm_core.c:59-85` obtains DES from the TLS
//!   backend. Every C TLS backend is dropped, so `des 0.8.1` is used
//!   directly by `auth/ntlm.rs`, which is where the pure-Rust NTLM lives.
//! * **No base64 and no hex *decode* tables.** `lib/curlx/base64.c` maps to
//!   `util/base64.rs`, which owns the alphabet, the decode table and the
//!   input cap. `util/strparse.rs` owns hex decoding. The
//!   `Sec-WebSocket-Key` base64 and the HTTP Digest `cnonce` base64 both
//!   route through `util/base64`, not through here.
//! * **No certificate-pinning helper and no `sha256sum` shim.** curl's own
//!   rustls backend advertises neither: `lib/vtls/rustls.c:1397-1426` sets
//!   exactly seven `SSLSUPP_*` flags and `SSLSUPP_PINNEDPUBKEY` is not among
//!   them, while `lib/vtls/rustls.c:1423` leaves the `sha256sum` vtable slot
//!   `NULL`. Building a pinning obligation in here would let `tls/` advertise
//!   a capability that is not implemented; under-reporting is safe,
//!   over-reporting is not.
//! * **No local error type.** Fallible operations return
//!   `crate::error::CURLcode`, whose discriminants are pinned to the C
//!   values. Success is `Ok(())`, never `CURLcode::Ok`.
//! * **No `tests/` subdirectory and no README.** Unit coverage lives in
//!   `#[cfg(test)]` modules inside each sibling; integration tests belong to a
//!   workspace-level test tree that does not exist yet.
//!
//! The five C unit tests that covered this code -- `tests/unit/unit1601.c`
//! (MD5), `unit1611.c` (MD4), `unit1610.c` (SHA-256), `unit1612.c`
//! (HMAC-MD5) and `unit1615.c` (SHA-512/256, eight vectors) -- all gate on
//! `<features>unittest</features>`, which this binary does not advertise, so
//! they skip. Their assertions are reproduced in the siblings' own test
//! modules. That is a recorded deviation, not a defect: those programs call
//! internal `Curl_*` symbols, and a Rust static library genuinely does not
//! place `pub(crate)` items in its symbol table. Re-exporting internals to
//! make them link would destroy the encapsulation this crate depends on, so
//! it is not done.
//!
//! # How to read the re-export surface
//!
//! The re-exports below are explicit and never glob. A glob would make the
//! surface unauditable and would silently re-export whatever a sibling adds
//! later. They are grouped, and each group records what it deliberately
//! leaves out.
//!
//! What is re-exported and what is not follows one rule: **a name is
//! re-exported only where the target layout fixes it unconditionally.** Two
//! items are deliberately absent for that reason -- `sha512_256`'s
//! incremental context, whose type name is chosen by that module, and
//! `hmac`'s generic `hmac` function, whose return type is chosen by that
//! module. Naming either here would be a guess that breaks the build.
//!
//! The same rule governs the contract block at the foot of the file. It
//! pins constant *values*, because those are fixed by the C parameter
//! tables, and pins only the *existence* of functions, because each sibling
//! is free to return a `Result` instead of a plain array. It also keeps
//! every re-export used: an unreferenced `pub(crate) use` is reported as an
//! unused import, and `#![allow(dead_code)]` does not suppress that -- the
//! two are separate lints, verified by measurement. Add a re-export without
//! recording it in the contract block and the build tells you.
//!
//! # Gates
//!
//! Every pattern below uses a character class so that these comment lines
//! cannot match themselves -- the gates stay runnable against this file
//! itself. Each class sits on the first letter on purpose: splitting a
//! word mid-way leaves a fragment that the spellchecker at
//! hygiene.yml:60-66 reports as a misspelling.
//!
//! ```sh
//! # This file adds no exemption to the crate-root safety attribute; the
//! # crate's sole exemption sits on the root's `mod ffi` declaration.
//! # Must print nothing.
//! grep -rnE '[u]nsafe' curl-rs-lib/src/crypto/
//!
//! # There is no `tls` feature. A cfg naming a feature that does not exist
//! # compiles the code away silently. Must print nothing.
//! grep -rnE 'feature *= *"[t]ls"' curl-rs-lib/src/crypto/
//!
//! # Exactly one licence identifier line. Must print 1.
//! grep -c 'SPDX-License-Ident[i]fier: curl' curl-rs-lib/src/crypto/mod.rs
//!
//! # No glob re-export (nothing), and six module declarations (6).
//! grep -n 'use .*::\*' curl-rs-lib/src/crypto/mod.rs
//! grep -c '^pub(crate) mod ' curl-rs-lib/src/crypto/mod.rs
//! ```
//!
//! The 15 real feature names are `http2`, `http3`, `ftp`, `ssh`,
//! `websockets`, `cookies`, `hsts`, `altsvc`, `doh`, `brotli`, `zstd`,
//! `gzip`, `negotiate`, `hickory-dns` and `memdebug`; the last three
//! default to off. None of them gates anything in this directory: digests
//! and randomness are unconditional.
//!
//! The only `as` tokens in this file are import renames, which disambiguate
//! the seven length constants. There is no numeric cast anywhere here, so
//! nothing can silently truncate.

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
// Every consumer named in section 1 -- `auth/`, `tls/`, `protocols/ws.rs`,
// `cookies/` -- lives in a module this crate has yet to grow. Until they exist,
// `grep -rn 'crypto::' curl-rs-lib/src curl-rs/src` finds only the
// `pub(crate) mod crypto;` declaration in `curl-rs-lib/src/lib.rs` and two
// `version.rs` sites: a documentation reference to `crate::crypto::rand`, and
// the one live call in the crate, `crate::crypto::sha512_256::available()`. So
// nearly every item here is genuinely unreferenced and each one would be
// reported, breaking the zero-warnings build gate for a condition that is a
// property of migration order rather than of this code. The same justification,
// on the same grounds, is recorded in `ffi/mod.rs`.
//
// SUPPRESSION IS PER ITEM, NOT PER MODULE. Each unreferenced item carries its
// own `#[allow(dead_code)]`, written where the item is, and there is no
// `#![allow(dead_code)]` on this module root -- `mod source_policy` in
// `curl-rs-lib/src/lib.rs` rejects one, because a root-scoped level also
// silences the NEXT item that loses its last caller, silently. The inventory of
// per-item allows is the record of what is still waiting for a consumer.
//
// None of this touches unused imports: `dead_code` and `unused_imports` are
// separate lints, measured. A `pub(crate) use` naming a module that does not
// exist is E0432, and one that exists but is referenced by nothing is an unused
// import; neither is silenced by a `dead_code` level. That is why the contract
// block at the foot of this file references every re-export, and why adding a
// re-export without recording it there is reported as an unused import.
//
// THE SIX PRIMITIVE MODULES ARE DECLARED, NOT DESCRIBED, because all six files
// exist: `md5.rs`, `md4.rs`, `sha256.rs`, `sha512_256.rs`, `hmac.rs` and
// `rand.rs`. A declaration without its file is E0583, which no `#[allow]`
// reaches, so each one arrives with its file -- and each one has. The seven
// length constants below are re-exported from the module that owns each digest
// rather than restated here, so the C oracle for every value stays next to the
// implementation it constrains.

/// MD5, RFC 1321. Supersedes `lib/md5.c` and `lib/curl_md5.h` over
/// `md-5 0.10.6`.
///
/// Consumed by HTTP Digest and by NTLM. Exposes the one-shot `md5`, the
/// incremental `Md5Context`, and the `Md5` marker type that `hmac` needs for
/// `Hmac<Md5>`. `lib/md5.c:528-535` fixes the keyed parameters at a 64-byte
/// block and a 16-byte result; `lib/md5.c:537-543` fixes the unkeyed result
/// at 16 bytes.
pub(crate) mod md5;

/// MD4, RFC 1320. Supersedes `lib/md4.c` and `lib/curl_md4.h` over
/// `md4 0.10.2`.
///
/// One consumer only: the NTLM password hash at `lib/curl_ntlm_core.c:425`.
/// A one-shot `md4` and nothing else -- curl never streams MD4 and never keys
/// it, so there is no incremental context and no HMAC parameter table to
/// reproduce.
pub(crate) mod md4;

/// SHA-256, FIPS 180-4. Supersedes `lib/sha256.c` and `lib/curl_sha256.h`
/// over `sha2 0.10.9`.
///
/// Consumed by HTTP Digest (the `-sess` and SHA-256 variants) and by AWS
/// SigV4. `lib/sha256.c:468-475` fixes the keyed parameters at a 64-byte
/// block and a 32-byte result.
pub(crate) mod sha256;

/// SHA-512/256, FIPS 180-4. Supersedes `lib/curl_sha512_256.c` and
/// `lib/curl_sha512_256.h` over `sha2 0.10.9`.
///
/// SHA-512 with a truncated initial state, so the block is 128 bytes and not
/// 64: `lib/curl_sha512_256.c:83` defines `CURL_SHA512_256_BLOCK_SIZE 128`
/// and `:788-804` fixes the keyed parameters at 128 and 32. Consumed by the
/// SHA-512-256 HTTP Digest algorithm.
pub(crate) mod sha512_256;

/// HMAC, RFC 2104. Supersedes `lib/hmac.c` and `lib/curl_hmac.h` over
/// `hmac 0.12.1`.
///
/// `lib/hmac.c:40-41` fixes the inner and outer pads at `0x36` and `0x5C`.
/// The C implementation was generic over a parameter table carrying a block
/// size, a result size and three function pointers; the Rust replacement is
/// generic over the `digest` traits instead, which is why one `digest`
/// generation across the graph is a hard requirement (section 4).
pub(crate) mod hmac;

/// Randomness. Supersedes `lib/rand.c` and `lib/rand.h` over `rand 0.8.7`.
///
/// Exposes an object-safe `Rng` trait so that callers which must not depend
/// on this directory -- `util/fopen.rs` above all -- can take randomness by
/// injection, and so that tests can substitute a deterministic source.
/// `lib/rand.c:236-241` rejects an odd output size and a request larger than
/// the 128-byte scratch buffer with `CURLE_BAD_FUNCTION_ARGUMENT`, and
/// `lib/rand.c:250` renders random bytes as *lowercase* hex -- see
/// `hex_lower` at the foot of this file.
pub(crate) mod rand;

// Re-export group A -- digest and block lengths, disambiguated
//
// Each sibling names its own constants `DIGEST_LEN` and `BLOCK_LEN`, which is
// right inside the module and useless across it: four of the six modules
// would collide. They are re-exported here under prefixed names so a caller
// choosing a buffer size cannot pick the wrong algorithm's length.
//
// The values are fixed by the C parameter tables -- `lib/md5.c:528-535`,
// `lib/curl_md5.h:32`, `lib/sha256.c:468-475`, `lib/curl_sha512_256.c:83`
// and `:788-804` -- so they are pinned by value in the contract block below.
// The 64-against-128 difference between SHA-256 and SHA-512/256 is the one
// that silently corrupts a keyed digest if conflated.
//
// MD4 contributes a digest length only: curl never keys MD4 and never streams
// it, so `md4` publishes no block length to re-export.

pub(crate) use md4::DIGEST_LEN as MD4_DIGEST_LEN;
pub(crate) use md5::BLOCK_LEN as MD5_BLOCK_LEN;
pub(crate) use md5::DIGEST_LEN as MD5_DIGEST_LEN;
pub(crate) use sha256::BLOCK_LEN as SHA256_BLOCK_LEN;
pub(crate) use sha256::DIGEST_LEN as SHA256_DIGEST_LEN;
pub(crate) use sha512_256::BLOCK_LEN as SHA512_256_BLOCK_LEN;
pub(crate) use sha512_256::DIGEST_LEN as SHA512_256_DIGEST_LEN;

// Re-export group B -- one-shot digests
//
// The whole-message form, which is what almost every call site in the C tree
// used: `Curl_md5it`, `Curl_md4it`, `Curl_sha256it` and `Curl_sha512_256it`.
// A function may share its module's name because modules live in the type
// namespace and functions in the value namespace, so `crypto::md5` resolves
// to the module in a path position and to the function in a call position.

pub(crate) use md4::md4;
pub(crate) use md5::md5;
pub(crate) use sha256::sha256;
pub(crate) use sha512_256::sha512_256;

// Re-export group C -- keyed digests
//
// The three concrete instantiations the C tree provided as parameter tables:
// `Curl_HMAC_MD5` (`lib/md5.c:528-535`), `Curl_HMAC_SHA256`
// (`lib/sha256.c:468-475`) and `Curl_HMAC_SHA512_256`
// (`lib/curl_sha512_256.c:788-804`).
//
// NOT re-exported, deliberately: the generic `hmac::hmac` and the generic
// `hmac::HmacContext`. Both are reachable as `crypto::hmac::hmac::<D>` and
// `crypto::hmac::HmacContext<D>`. The generic function's return type is
// chosen by that module -- a plain array or a `GenericArray`, whichever keeps
// its call sites clean -- so naming it here would be a guess, and a generic
// item cannot be referenced in the contract block without supplying the type
// parameter it is meant to be generic over.

pub(crate) use hmac::hmac_md5;
pub(crate) use hmac::hmac_sha256;
pub(crate) use hmac::hmac_sha512_256;

// Re-export group D -- incremental digests
//
// `Md5Context` reproduces a real C API: `lib/curl_md5.h:59-63` declares
// `Curl_MD5_init` / `_update` / `_final` over the `MD5_params` vtable at
// `lib/curl_md5.h:41-43`, and `lib/vauth/digest.c:388`, `:402`, `:425`,
// `:443` and `lib/pop3.c:574` all feed a digest in pieces through it.
//
// `Sha256Context` has no C counterpart -- `lib/curl_sha256.h:40` declares only
// the one-shot `Curl_sha256it` -- and exists so that a caller which must feed
// data incrementally has one shape for both algorithms. That is an internal
// convenience with no observable effect: the bytes a streamed digest produces
// are the bytes the one-shot form produces.
//
// NOT re-exported, deliberately: the SHA-512/256 incremental context. Its
// type name is chosen by `sha512_256` itself, because the obvious spelling
// would trip `clippy::non_camel_case_types` and the module is free to pick
// among the admissible alternatives. Callers reach it through
// `crypto::sha512_256`. Also absent: the `Md4` marker type, which `md4`
// publishes only optionally, since nothing keys or streams MD4.

pub(crate) use md5::Md5Context;
pub(crate) use sha256::Sha256Context;

// Re-export group E -- randomness
//
// `Rng` is object-safe on purpose. `util/fopen.rs` needs random temporary
// filenames but must not import this directory (section 3), so it accepts a
// `&mut dyn Rng` from its caller instead. `TestRng` is not behind
// `#[cfg(test)]` for the same reason: a sibling or an integration test needs
// a deterministic source without a test-only build.
//
// NOT re-exported, deliberately: the alphabet constant behind `rand_alnum`,
// which is an implementation detail of that one function.

pub(crate) use rand::rand_alnum;
pub(crate) use rand::rand_bytes;
pub(crate) use rand::rand_hex;
pub(crate) use rand::Rng;
pub(crate) use rand::SystemRng;
pub(crate) use rand::TestRng;

// Shared policy owned by this file -- digest-to-ASCII rendering
//
// This is the one piece of behaviour that belongs to the directory as a whole
// rather than to any single primitive, because every algorithm here is
// rendered the same way and getting the case wrong is invisible until an
// authentication exchange fails against a real server.

/// Size of the C destination buffer for an MD5 digest rendered as ASCII: two
/// characters per byte plus the terminating NUL.
///
/// `lib/vauth/digest.c:133-141` declares
/// `auth_digest_md5_to_ascii(const unsigned char *source /* 16 bytes */,
/// unsigned char *dest /* 33 bytes */)`. Rust strings carry their own length
/// and need no terminator, so `hex_lower` returns 32 characters for a 16-byte
/// digest; the constant keeps the correspondence with the C call site
/// auditable, and any code that hands a buffer to C sizes it from here.
#[allow(dead_code)]
pub(crate) const MD5_HEX_BUF_LEN: usize = 33;

/// Size of the C destination buffer for a SHA-256 digest rendered as ASCII.
///
/// `lib/vauth/digest.c:143-151` declares
/// `auth_digest_sha256_to_ascii(const unsigned char *source /* 32 bytes */,
/// unsigned char *dest /* 65 bytes */)`, and `lib/http_aws_sigv4.c` uses the
/// same 65 for its own `SHA256_HEX_LENGTH`. SHA-512/256 also produces 32
/// bytes, so this length covers it too.
#[allow(dead_code)]
pub(crate) const SHA256_HEX_BUF_LEN: usize = 65;

/// Render bytes as **lowercase** hexadecimal ASCII, with no separators and no
/// prefix.
///
/// Lowercase is not a preference; it is the wire format. Every digest curl
/// puts on the wire is rendered with `"%02x"`:
/// `lib/vauth/digest.c:133-141` and `:143-151` both call
/// `curl_msnprintf(&dest[i * 2], 3, "%02x", source[i])`, and
/// `lib/escape.c:195-217` documents `Curl_hexencode` as converting "binary
/// input to lowercase hex-encoded ASCII output", indexing the lowercase
/// table `Curl_ldigits` at `lib/mprintf.c:36`.
///
/// The trap is one function away. `lib/escape.c:218-227` documents
/// `Curl_hexbyte` as emitting "a two-digit UPPERCASE hex number" and indexes
/// `Curl_udigits` at `lib/mprintf.c:39`. HTTP Digest, NTLM and AWS SigV4 all
/// take the **lowercase** path; nothing in this directory wants the uppercase
/// one, and it is deliberately not provided here.
///
/// ```text
///   [0x00, 0x0f, 0xa0, 0xff]  ->  "000fa0ff"
///   16-byte MD5 digest        ->  32 characters (C wrote 33 with the NUL)
///   32-byte SHA-256 digest    ->  64 characters (C wrote 65 with the NUL)
/// ```
///
/// Implemented over `hex 0.4.3`, whose `encode` is lowercase by definition.
/// Hand-rolling a nibble table here would duplicate `hex` for no gain, and
/// hex *decoding* is not this directory's business at all: `util/strparse.rs`
/// owns that, mirroring `curlx_hexasciitable`.
#[allow(dead_code)]
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// Value and existence contracts
//
// Two jobs, both discharged at compile time and both costing nothing at run
// time. These are `const` items, so they are evaluated during compilation,
// run no destructor and are inert under Miri.
//
// 1. They pin what the C tree fixes. A digest length is not an implementation
//    choice: it comes from the parameter tables cited in group A. Writing the
//    value here means a sibling that changes one breaks the build in this
//    file, next to the citation that explains why it cannot change.
//
// 2. They keep every re-export referenced. An unreferenced `pub(crate) use`
//    is an unused import, `#![allow(dead_code)]` does not cover that lint,
//    and the build gate admits no warnings. Add a re-export above without a
//    line here and the compiler says so.
//
// What is deliberately NOT pinned: function signatures. Each sibling is free
// to return `Result<_, CURLcode>` instead of a plain array, and `rand_hex`
// and `rand_alnum` may fill a caller-supplied slice instead of returning a
// `String`. Pinning a signature would forbid a choice the target design
// explicitly leaves open, so only existence is asserted -- `let _ = f;` names
// the function item without constraining its type.

const _: () = assert!(MD5_DIGEST_LEN == 16);
const _: () = assert!(MD5_BLOCK_LEN == 64);
const _: () = assert!(MD4_DIGEST_LEN == 16);
const _: () = assert!(SHA256_DIGEST_LEN == 32);
const _: () = assert!(SHA256_BLOCK_LEN == 64);
const _: () = assert!(SHA512_256_DIGEST_LEN == 32);

// The single most consequential constant in this directory. SHA-512/256 is
// SHA-512 truncated, so its block is twice SHA-256's despite the identical
// digest length above (`lib/curl_sha512_256.c:83`).
const _: () = assert!(SHA512_256_BLOCK_LEN == 128);
const _: () = assert!(SHA512_256_BLOCK_LEN == SHA256_BLOCK_LEN * 2);

// The ASCII buffer lengths are derived from the digest lengths, not chosen
// independently, so the derivation itself is asserted.
const _: () = assert!(MD5_HEX_BUF_LEN == MD5_DIGEST_LEN * 2 + 1);
const _: () = assert!(SHA256_HEX_BUF_LEN == SHA256_DIGEST_LEN * 2 + 1);
const _: () = assert!(SHA256_HEX_BUF_LEN == SHA512_256_DIGEST_LEN * 2 + 1);

// Types must exist and be sized. `&dyn Rng` additionally asserts that `Rng`
// stayed object-safe, which is the property `util/fopen.rs` depends on.
const _: Option<Md5Context> = None;
const _: Option<Sha256Context> = None;
const _: Option<SystemRng> = None;
const _: Option<TestRng> = None;
const _: Option<&dyn Rng> = None;

// Entry points must exist under these exact names.
const _: () = {
    let _ = md5;
    let _ = md4;
    let _ = sha256;
    let _ = sha512_256;
    let _ = hmac_md5;
    let _ = hmac_sha256;
    let _ = hmac_sha512_256;
    let _ = rand_bytes;
    let _ = rand_hex;
    let _ = rand_alnum;
};

// Tests -- scoped to what this file itself owns
//
// The primitives are tested where they live: the assertions of
// `tests/unit/unit1601.c` (MD5), `unit1611.c` (MD4), `unit1610.c`
// (SHA-256), `unit1612.c` (HMAC-MD5) and `unit1615.c` (SHA-512/256) belong
// in the siblings' own test modules. What is testable here is the rendering
// policy and the constants, and nothing below depends on a sibling's function
// signature, so a sibling exercising a documented alternative form cannot
// break these.

#[cfg(test)]
#[test]
fn hex_lower_matches_the_c_percent_02x_rendering() {
    // The nibble boundaries, which is where a hand-rolled table goes wrong:
    // both nibbles zero, a low nibble alone, a high nibble alone, both
    // nibbles set, and a value whose two nibbles differ.
    assert_eq!(hex_lower(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    assert_eq!(hex_lower(&[0x01]), "01");
    assert_eq!(hex_lower(&[0x10]), "10");
    assert_eq!(hex_lower(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
}

#[cfg(test)]
#[test]
fn hex_lower_never_emits_an_uppercase_digit() {
    // Curl_hexbyte (lib/escape.c:218-227) is the uppercase one and must not
    // be what this helper reproduces. Every byte value is checked, so the
    // assertion cannot pass by accident on a lucky sample.
    let all: Vec<u8> = (0u8..=255).collect();
    let rendered = hex_lower(&all);
    assert!(!rendered.chars().any(|c| c.is_ascii_uppercase()));
    assert!(rendered.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(rendered.starts_with("000102"));
    assert!(rendered.ends_with("fdfeff"));
}

#[cfg(test)]
#[test]
fn hex_lower_of_no_bytes_is_the_empty_string() {
    assert_eq!(hex_lower(&[]), "");
    assert!(hex_lower(&[]).is_empty());
}

#[cfg(test)]
#[test]
fn hex_lower_emits_two_characters_per_byte() {
    for len in 0..=64usize {
        let input = vec![0x5au8; len];
        assert_eq!(hex_lower(&input).len(), len * 2);
    }
}

#[cfg(test)]
#[test]
fn rendered_digests_fill_the_c_buffers_exactly() {
    // The C helpers wrote a NUL, so the rendered length is one less than the
    // destination size at lib/vauth/digest.c:135 and :145.
    let md5_digest = [0xa5u8; MD5_DIGEST_LEN];
    assert_eq!(hex_lower(&md5_digest).len(), MD5_HEX_BUF_LEN - 1);

    let sha256_digest = [0x5au8; SHA256_DIGEST_LEN];
    assert_eq!(hex_lower(&sha256_digest).len(), SHA256_HEX_BUF_LEN - 1);

    // SHA-512/256 shares the 32-byte digest length, so it shares the buffer.
    let sha512_256_digest = [0x3cu8; SHA512_256_DIGEST_LEN];
    assert_eq!(hex_lower(&sha512_256_digest).len(), SHA256_HEX_BUF_LEN - 1);
}

#[cfg(test)]
#[test]
fn block_lengths_are_not_interchangeable() {
    // Asserted as a runtime test in addition to the const assertions above,
    // so a failure names the algorithms rather than only a line number.
    assert_eq!(MD5_BLOCK_LEN, 64);
    assert_eq!(SHA256_BLOCK_LEN, 64);
    assert_eq!(SHA512_256_BLOCK_LEN, 128);
    assert_ne!(SHA256_BLOCK_LEN, SHA512_256_BLOCK_LEN);
    assert_eq!(SHA256_DIGEST_LEN, SHA512_256_DIGEST_LEN);
}
