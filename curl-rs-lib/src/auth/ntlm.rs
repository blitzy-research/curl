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
//! NTLM authentication: the three messages, their cryptography, and the
//! HTTP exchange that carries them.
//!
//! Supersedes three C files, 1,780 lines measured with `wc -l`:
//!
//! ```text
//!   lib/vauth/ntlm.c        859   the three messages and their layouts
//!   lib/curl_ntlm_core.c    667   DES, MD4, HMAC-MD5 and the v2 blob
//!   lib/http_ntlm.c         254   the five-state HTTP exchange
//!                          ----
//!                          1780
//! ```
//!
//! plus the two-macro helper header `lib/curl_ntlm_core.h:33-35`. Every
//! claim below carries a `path:line` citation into the C tree, because the
//! bytes being reproduced are defined by those files and by the fixture
//! corpus, not by this description.
//!
//! # Every byte here is a wire byte
//!
//! NTLM messages are binary structures wrapped in base64. 53 fixtures gate
//! on the `NTLM` feature and each of them compares the resulting header line
//! inside a byte-exact `<protocol>` block: `tests/getpart.pm:351+`'s
//! `compareparts` joins both sides into a single string and compares them
//! whole, with no per-line matching, no normalisation and no reordering. One
//! wrong byte, one reordered security buffer or one recomputed constant fails
//! outright. A mismatch is a defect here and never a reason to edit a
//! fixture.
//!
//! Two consequences run through the whole file. Offsets and lengths are
//! written as the literals the C writes -- `0x18` stays `0x18` even where a
//! variable holds the same number -- and every conversion is explicit, so a
//! width narrowing cannot silently produce a well-formed but wrong message.
//!
//! # What is NOT ported, and why
//!
//! * **`lib/vauth/ntlm_sspi.c`** (353 lines): the Windows SSPI
//!   implementation, outside the four-target matrix. `lib/vauth/ntlm.c` is
//!   already the non-SSPI arm in its entirety -- `:26` opens
//!   `#if defined(USE_NTLM) && !defined(USE_WINDOWS_SSPI)` and `:859` closes
//!   it -- so there was no SSPI content in the migration source to strip.
//!   The SSPI half of `struct ntlmdata` (`lib/vauth/vauth.h:164-179`:
//!   `credentials`, `context`, `identity`, `token_max`, `output_token`,
//!   `input_token`, `spn` and the Schannel-binding `sslContext`) is likewise
//!   absent from [`NtlmData`].
//! * **The `#if DEBUG_ME` blocks** of `lib/vauth/ntlm.c`, roughly 158 lines.
//!   `:35` defines `DEBUG_ME 0`, so `ntlm_print_flags` (`:162-226`),
//!   `ntlm_print_hex` (`:228-237`) and the five `DEBUG_OUT({...})` call sites
//!   are dead code in every shipped build. They are not ported. The **flag
//!   constants** those blocks guard are ported, because a flag word arriving
//!   from a server sets bits regardless of whether curl can print their
//!   names, and naming them is what makes [`NtlmFlags`]'s formatter useful.
//! * **Five of the six DES backends.** `lib/curl_ntlm_core.c:59-113`
//!   dispatches between `USE_OPENSSL_DES` (covering both OpenSSL and
//!   wolfSSL), `USE_GNUTLS`, `USE_MBEDTLS_DES`, `USE_OS400CRYPTO`,
//!   `USE_WIN32_CRYPTO` and an `#else` arm that is a hard `#error`. All of it
//!   collapses to one `des 0.8.1` implementation, because every C TLS backend
//!   is dropped.
//! * **The 32-bit `time_t` arm** of `time2filetime`
//!   (`lib/curl_ntlm_core.c:452-486`, 35 lines of split-shift arithmetic to
//!   avoid a 64-bit multiply). All four mandated targets are 64-bit, so only
//!   the `#if SIZEOF_TIME_T > 4` arm at `:448-451` applies.
//! * **`NTLM_WB`**, the winbind helper. Removed upstream in 8.8.0 and absent
//!   from all three source files. It is not implemented and, decisively, is
//!   **never advertised**: the harness reads the `Features:` line of
//!   `curl --version` to decide which fixtures to run, and over-reporting a
//!   capability turns a clean skip into a failure. `crate::version` emits no
//!   `NTLM_WB` token.
//!
//! Two preprocessor guards have no Cargo successor. `lib/curl_ntlm_core.c:26`
//! wraps that file in `#ifdef USE_CURL_NTLM_CORE` and `:434` guards the v2
//! helpers with `#ifndef USE_WINDOWS_SSPI`; this crate declares exactly
//! fifteen features and none of them is `ntlm`, while SSPI is out of the
//! matrix. Everything below is therefore unconditionally present. The same
//! holds for `CURL_DISABLE_PROXY` at `lib/http_ntlm.c:141-152`: see
//! [`output_ntlm`].
//!
//! # The three message layouts, transcribed
//!
//! A `short` is a little-endian 16-bit unsigned value and a `long` a
//! little-endian 32-bit one. A **security buffer** is the triplet
//! `lib/vauth/ntlm.c:297-303` describes: a `short` length, a `short`
//! allocated size, and a `long` offset from the start of the message. All
//! three messages open with the eight-byte [`NTLMSSP_SIGNATURE`].
//!
//! Type-1, `lib/vauth/ntlm.c:431-443`. 32 bytes, always:
//!
//! ```text
//!    0   NTLMSSP Signature      8 bytes ("NTLMSSP" and its NUL)
//!    8   NTLM Message Type      long (0x01000000)
//!   12   Flags                  long
//!  (16)  Supplied Domain        security buffer (*)
//!  (24)  Supplied Workstation   security buffer (*)
//!  (32)  OS Version Structure   8 bytes (*)     -- not emitted
//!                                      (*) -> Optional
//! ```
//!
//! Type-2, `lib/vauth/ntlm.c:341-355`, received:
//!
//! ```text
//!    0   NTLMSSP Signature      8 bytes
//!    8   NTLM Message Type      long (0x02000000)
//!   12   Target Name            security buffer
//!   20   Flags                  long
//!   24   Challenge              8 bytes
//!  (32)  Context                8 bytes (two consecutive longs) (*)
//!  (40)  Target Information     security buffer (*)
//!  (48)  OS Version Structure   8 bytes (*)
//!                                      (*) -> Optional
//! ```
//!
//! Type-3, `lib/vauth/ntlm.c:550-566`. A 64-byte header, then the responses
//! and strings the header points at:
//!
//! ```text
//!    0   NTLMSSP Signature      8 bytes
//!    8   NTLM Message Type      long (0x03000000)
//!   12   LM/LMv2 Response       security buffer
//!   20   NTLM/NTLMv2 Response   security buffer
//!   28   Target Name            security buffer
//!   36   username               security buffer
//!   44   Workstation Name       security buffer
//!  (52)  Session Key            security buffer (*)
//!  (60)  Flags                  long (*)
//!  (64)  OS Version Structure   8 bytes (*)     -- not emitted
//!                                      (*) -> Optional
//! ```
//!
//! The NTLMv2 response is itself a structure,
//! `lib/curl_ntlm_core.c:554-567`:
//!
//! ```text
//!    0   HMAC MD5               16 bytes
//!  ------ BLOB ---------------------------------------------------------
//!   16   Signature              0x01010000
//!   20   Reserved               long (0x00000000)
//!   24   Timestamp              LE 64-bit, tenths of a microsecond since
//!                               January 1, 1601
//!   32   Client Nonce           8 bytes
//!   40   Unknown                4 bytes
//!   44   Target Info            N bytes (from the type-2 message)
//! 44+N   Unknown                4 bytes
//! ```
//!
//! # The identity in a type-1 message is empty, and the type-3 hostname is
//! # a constant. Both are fixture-confirmed.
//!
//! This is the most surprising fact in the file and the one most likely to be
//! "improved" into a defect.
//!
//! `Curl_auth_create_ntlm_type1_message` declares `host` and `domain` as
//! empty strings with all lengths and offsets zero (`lib/vauth/ntlm.c:448-454`)
//! and then discards all four of its identity parameters outright:
//! `(void)userp; (void)passwdp; (void)service; (void)hostname;` at `:456-459`.
//! A type-1 message carries no identity whatsoever, which is why
//! [`create_type1_message`] takes none.
//!
//! The type-3 hostname is `static const char host[] = "WORKSTATION"`
//! (`lib/vauth/ntlm.c:579-581`) with curl's own justification: *"The fixed
//! hostname we provide, in order to not leak our real local host name. Copy
//! the name used by Firefox."* The real hostname is never consulted --
//! `Curl_gethostname`'s only caller anywhere in the tree is the out-of-scope
//! `lib/smtp.c:191`, and no fixture references it -- so nothing in this file
//! calls `crate::ffi::sys`. `tests/data/test1008`'s expected type-3 base64
//! ends `dGVzdHVzZXJXT1JLU1RBVElPTg`, which decodes to `testuser` followed
//! by `WORKSTATION`.
//!
//! # The fixture corpus exercises NTLMv1 only, and NTLMv1 is deterministic
//!
//! An NTLMv2 message contains a random client challenge and a timestamp,
//! which appears to make byte-exact comparison impossible. It does not, and
//! the reasoning is recorded here so that nobody later concludes the NTLM
//! fixtures are unpassable and starts editing them.
//!
//! `tests/data/test1008`'s mock server sends a type-2 whose flag word at
//! bytes 20 through 23 is `86 82 01 00`, that is `0x0001_8286`. Bit 19,
//! [`NTLMFLAG_NEGOTIATE_NTLM2_KEY`], is **clear**, so
//! [`create_type3_message`] takes the version-1 branch
//! (`lib/vauth/ntlm.c:608`). NTLMv1 is DES over the server-supplied
//! challenge alone: no client entropy, no timestamp, nothing that varies
//! between runs. The expected type-3 confirms it -- 24-byte responses,
//! `userlen` 8 rather than 16 so not Unicode, `hostlen` 11 rather than 22,
//! and offsets 64, 88, 112, 112, 120.
//!
//! Byte-exactness for the NTLM fixtures therefore needs no control over
//! randomness or the clock. The harness arranges both anyway --
//! `tests/runner.pm:166` deletes `CURL_ENTROPY` and `:167` sets
//! `CURL_FORCETIME=1`, "for debug NTLM magic" -- and this file honours the
//! same seams by injection rather than by reading the environment:
//!
//! * The client challenge is drawn from an injected
//!   [`crate::crypto::rand::Rng`], never from a global.
//! * The timestamp comes from an injected [`Clock`]. That subsumes
//!   `CURL_FORCETIME` exactly: the C's forced path is
//!   `time2filetime(&tw, (time_t)0)` (`lib/curl_ntlm_core.c:579-580`), and a
//!   clock whose `epoch_secs()` reads zero produces the identical eight
//!   bytes. Choosing when to force is the caller's decision, made where the
//!   environment is already being read, not here.
//!
//! # Credentials
//!
//! This module adds no logging. curl does not redact an `Authorization:`
//! header and this file does not start: `lib/http.c:2888-2895` places the
//! fully formed line into the request buffer, from where `--verbose` prints
//! it verbatim, and 168 fixtures compare that line byte for byte.
//! Suppressing it would fail them.
//!
//! What binds instead is narrower and absolute: **no secret gains a path to
//! output that curl does not already have.** The password, the LM hash, the
//! NT hash, the NTLMv2 hash, the LM and NT responses and the client
//! challenge are never traced, and the two types that hold key material --
//! [`LmHash`] and [`NtHash`] -- carry hand-written formatters that print a
//! placeholder. A 21-byte key buffer is password-equivalent: it is exactly
//! what an offline cracker needs.
//!
//! The five diagnostics curl does emit are reproduced verbatim, because they
//! reach the user through `--verbose` and are therefore frozen output.
//!
//! # Position in the three orderings
//!
//! All three live in [`super`] and none is duplicated here. NTLM is fourth
//! of six in preference (`PREFERENCE_ORDER`, from `pickoneauth()` at
//! `lib/http.c:343-364`), third in emission (`EMISSION_ORDER`) and
//! second in challenge parsing (`CHALLENGE_ORDER`), and the clamp to
//! HTTP/1.1 that NTLM forces on a connection speaking anything better lives
//! in `super::auth_act` behind `NTLM_FORCE_HTTP11`.

use core::fmt;

use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;

use crate::crypto::hmac::hmac_md5;
use crate::crypto::md4::md4;
use crate::crypto::rand::Rng;
use crate::error::CURLcode;
use crate::trace::{failf, infof, Tracer};
use crate::util::base64;
use crate::util::strcase::{checkprefix, raw_toupper, strntoupper};
use crate::util::timeval::Clock;

use super::{
    authorization_header, AuthContext, AuthEmission, AuthMask, AuthScheme,
    Credentials, HttpAuthMechanism, MechanismSlots, REDACTED_PLACEHOLDER,
};

// ---------------------------------------------------------------------------
// Constants. Every one of these is a wire byte or a wire offset.
// ---------------------------------------------------------------------------

/// The `"NTLMSSP"` signature every message opens with, **eight** bytes.
///
/// `lib/vauth/ntlm.c:45` writes it as a seven-byte string literal, with the
/// comment *"'NTLMSSP' signature is always in ASCII regardless of the
/// platform"*:
///
/// ```c
/// #define NTLMSSP_SIGNATURE "\x4e\x54\x4c\x4d\x53\x53\x50"
/// ```
///
/// Seven bytes of text, but **eight bytes on the wire**. The C relies on the
/// implicit NUL terminator of the literal: the type-1 and type-3 format
/// strings append an explicit `"%c"` fed a zero (`:464-465`, `:683-684`,
/// documented there as "trailing zero"), and the type-2 validator compares
/// **eight** bytes with `memcmp(type2, NTLMSSP_SIGNATURE, 8)` (`:364`),
/// reading the terminator as data.
///
/// Declaring the terminator explicitly is therefore not a stylistic choice.
/// A seven-byte constant here would shift every subsequent field by one and
/// fail every NTLM fixture, and it would make the type-2 comparison accept a
/// message whose eighth byte is anything at all.
#[rustfmt::skip]
pub(crate) const NTLMSSP_SIGNATURE: [u8; 8] = [
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
];

/// `#define NTLM_BUFSIZE 1024` -- `lib/vauth/ntlm.c:48`, whose comment reads
/// *"NTLM buffer fixed size, large enough for long user + host + domain"*.
///
/// The C declares `unsigned char ntlmbuf[NTLM_BUFSIZE]` on the stack
/// (`:570`) and bounds every append against it. Nothing here needs a fixed
/// allocation -- a [`Vec`] grows -- but the **bound is behaviour**: two
/// guards in [`create_type3_message`] compare against it and fail the
/// transfer with [`CURLcode::TooLarge`] when it would be exceeded. Dropping
/// the bound would accept credentials the C rejects, which is a behaviour
/// change and therefore prohibited.
pub(crate) const NTLM_BUFSIZE: usize = 1024;

/// The fixed size of the type-1 message: 32 bytes.
///
/// `lib/vauth/ntlm.c:500` computes `size = 32 + hostlen + domlen` where both
/// lengths are zero by construction (`:450-451`), so the sum is a constant.
/// It is named because two fixtures assert it -- `tests/data/test1008:108`
/// and `tests/data/test1021:118` both expect exactly 32 bytes -- and because
/// a reader checking this file against those fixtures should not have to add
/// up a format string to find it.
pub(crate) const TYPE1_SIZE: usize = 32;

/// The fixed size of the type-3 header, before the responses and strings.
///
/// `lib/vauth/ntlm.c:761` asserts it: `DEBUGASSERT(size == 64)` immediately
/// after the header is formatted. It is also `lmrespoff`, which `:762`
/// asserts as well.
pub(crate) const TYPE3_HEADER_SIZE: usize = 64;

/// The length of an LM, LMv2, NTLM or NTLMv2-session response: 24 bytes.
///
/// The C writes this as the bare literal `0x18` at six places
/// (`lib/vauth/ntlm.c:572`, `:575`, `:609`, `:646-647`, `:676`, `:728-730`,
/// `:765-767`) and as the initialiser `ntresplen = 24` at `:574`. The two
/// spellings are the same number; both are reproduced through this constant
/// **except** in the type-3 LM security buffer, where the literal is
/// deliberately kept -- see [`create_type3_message`].
pub(crate) const RESPONSE_LEN: usize = 0x18;

/// The length of the challenge a type-2 message carries, and of the client
/// challenge a type-3 message answers with: 8 bytes.
///
/// `lib/vauth/vauth.h:182` (`unsigned char nonce[8]`),
/// `lib/vauth/ntlm.c:372` (`memcpy(ntlm->nonce, &type2[24], 8)`) and
/// `lib/vauth/ntlm.c:610`, `:617` (`unsigned char entropy[8]`,
/// `Curl_rand(data, entropy, 8)`).
pub(crate) const CHALLENGE_LEN: usize = 8;

/// The length of the 21-byte key buffer an LM or NT hash is expanded into.
///
/// Three 56-bit DES keys laid end to end: 7 + 7 + 7. `lib/curl_ntlm_core.c`
/// declares the buffers as `unsigned char ntbuffer[0x18]` (`:609`, `:646`)
/// -- 24 bytes, three more than are used -- while the functions that fill
/// them write 16 bytes of digest and then `memset(buffer + 16, 0, 21 - 16)`
/// (`:390`, `:427`), and `Curl_ntlm_core_lm_resp` reads exactly 21
/// (`:308-310`: *"takes a 21 byte array and treats it as 3 56-bit DES
/// keys"*).
///
/// 21 is the length that is actually contractual, so that is the length
/// [`LmHash`] and [`NtHash`] have. The C's three spare bytes are an
/// artefact of sizing two buffers to `0x18` and are not part of any
/// computation.
pub(crate) const HASH_KEY_LEN: usize = 21;

/// The `"NTLM"` scheme token, in both directions.
///
/// Matched inbound by `checkprefix("NTLM", header)` (`lib/http_ntlm.c:63`,
/// whose `header += strlen("NTLM")` at `:68` also derives the skip from it)
/// and written outbound as the scheme of
/// `"%sAuthorization: NTLM %s\r\n"` (`:207`, `:225`).
///
/// [`AuthScheme::Ntlm`]`.header_scheme()` returns the same four bytes and is
/// what [`output_ntlm`] passes to [`authorization_header`]; this constant
/// exists for the inbound side, where the C spells the literal directly.
pub(crate) const NTLM_SCHEME: &str = "NTLM";

/// The default service name: `"HTTP"`.
///
/// `lib/http_ntlm.c:145-146` and `:158-159`, both of the form
/// `data->set.str[STRING_SERVICE_NAME] ? ... : "HTTP"`. The service reaches
/// `Curl_auth_create_ntlm_type1_message` and is discarded there
/// (`lib/vauth/ntlm.c:458`), so it never affects a byte of NTLM output; the
/// constant is recorded because the option exists and a reader comparing
/// this file against `lib/http_ntlm.c` should find it accounted for.
///
/// The allowance is an inventory entry rather than a suppression: the value
/// has no consumer BY CONSTRUCTION, because the only function it could reach
/// discards it. Deleting it instead would leave `CURLOPT_SERVICE_NAME`
/// unaccounted for in the one module a reader would check for it.
#[allow(dead_code)]
pub(crate) const DEFAULT_SERVICE: &str = "HTTP";

/// The workstation name a type-3 message reports: `"WORKSTATION"`.
///
/// `static const char host[] = "WORKSTATION"` --
/// `lib/vauth/ntlm.c:579-581`, with the comment *"The fixed hostname we
/// provide, in order to not leak our real local host name. Copy the name
/// used by Firefox."*
///
/// Eleven bytes, which `:606` derives as `sizeof(host) - 1`. It is a
/// constant on purpose and must not be replaced by the host's real name:
/// doing so would leak it and would fail every type-3 fixture. See the
/// module documentation for the decoded evidence from
/// `tests/data/test1008`.
pub(crate) const TYPE3_WORKSTATION: &[u8] = b"WORKSTATION";

/// The four bytes at offset 8 of a type-1 message: `0x01000000` as written.
///
/// `lib/vauth/ntlm.c:465` spells it `"\x01%c%c%c"` with three zero
/// arguments, commented "32-bit type = 1": one byte of `0x01` followed by
/// three zeroes, which is the little-endian encoding of 1.
#[rustfmt::skip]
const TYPE1_MARKER: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// The four bytes a type-2 message must carry at offset 8.
///
/// `static const char type2_marker[] = { 0x02, 0x00, 0x00, 0x00 }` --
/// `lib/vauth/ntlm.c:339`, compared with
/// `memcmp(type2 + 8, type2_marker, sizeof(type2_marker))` at `:365`.
#[rustfmt::skip]
const TYPE2_MARKER: [u8; 4] = [0x02, 0x00, 0x00, 0x00];

/// The four bytes at offset 8 of a type-3 message: `0x03000000` as written.
///
/// `lib/vauth/ntlm.c:684`, `"\x03%c%c%c"`, commented "32-bit type = 3".
#[rustfmt::skip]
const TYPE3_MARKER: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

/// The signature that opens the NTLMv2 blob: `0x01010000` as written.
///
/// `#define NTLMv2_BLOB_SIGNATURE "\x01\x01\x00\x00"` --
/// `lib/curl_ntlm_core.c:436`, written at blob offset 0, which is offset 16
/// of the response.
#[rustfmt::skip]
const NTLMV2_BLOB_SIGNATURE: [u8; 4] = [0x01, 0x01, 0x00, 0x00];

/// The `"KGS!@#$%"` plaintext the LM hash encrypts.
///
/// `lib/curl_ntlm_core.c:357-359`, whose comment spells it out:
///
/// ```c
/// static const unsigned char magic[] = {
///   0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 /* i.e. KGS!@#$% */
/// };
/// ```
///
/// Kept as bytes rather than as `b"KGS!@#$%"` so that it reads against the C
/// without a mental transliteration, and so that no formatter can reflow it
/// into something a reviewer cannot check byte by byte.
#[rustfmt::skip]
const LM_HASH_MAGIC: [u8; 8] = [
    0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25,
];

/// The maximum password length the LM hash considers: 14 bytes.
///
/// `size_t len = CURLMIN(strlen(password), 14)` --
/// `lib/curl_ntlm_core.c:360`. Two 56-bit DES keys hold 14 bytes and the
/// algorithm has no provision for more, so a longer password is **truncated,
/// not rejected**. That is a property of LM, not a defect in curl, and it is
/// reproduced exactly.
const LM_PASSWORD_MAX: usize = 14;

/// `CURL_MAX_INPUT_LENGTH` -- 8,000,000.
///
/// `lib/urldata.h` fixes it and `lib/curl_ntlm_core.c:512` is the one place
/// in this file's sources that consults it, rejecting a username or domain
/// longer than this from [`mk_ntlmv2_hash`]. Transcribed here rather than
/// imported because no module of this crate owns the option-validation
/// vocabulary yet, and because a second definition of a frozen constant is
/// caught by the test that asserts its value.
const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

/// Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch.
///
/// `lib/curl_ntlm_core.c:449`, and the 32-bit arm at `:465-466` states the
/// derivation: *"134774 days = 11644473600 seconds = 0x2B6109100"*.
const FILETIME_EPOCH_BIAS_SECS: u64 = 11_644_473_600;

/// Tenths of a microsecond in one second: the FILETIME tick rate.
///
/// `lib/curl_ntlm_core.c:449` multiplies by this, and `:560-561` names the
/// unit: *"64-bit signed value representing the number of tenths of a
/// microsecond since January 1, 1601"*.
const FILETIME_TICKS_PER_SEC: u64 = 10_000_000;

// ---------------------------------------------------------------------------
// The flag vocabulary. `lib/vauth/ntlm.c:50-159`, in bit order.
// ---------------------------------------------------------------------------

// The C's own header for this block, `:50-51`, cites its source: "Flag bits
// definitions based on https://davenport.sourceforge.net/ntlm.html".
//
// Seventeen of the twenty-four defined names sit inside `#if DEBUG_ME` blocks
// (`:64-80`, `:85-104`, `:110-123`, `:129-138`, `:144-159`) and so are absent
// from every shipped build. They are transcribed here anyway, for a reason
// that is not symmetry: a type-2 flag word arrives from a server and sets
// whichever bits it likes, and `NtlmFlags`'s formatter is the only place in
// this crate that can say which. NO BEHAVIOUR is attached to any of them --
// `create_type3_message` reads exactly two, UNICODE and NTLM2_KEY, and
// `decode_type2_message` reads one, TARGET_INFO. The others are vocabulary.
//
// The comment on each is curl's own, condensed. The bit positions are not
// negotiable: they are what a server sends and what a server parses.

/// Unicode strings are supported in security buffer data -- bit 0.
///
/// `lib/vauth/ntlm.c:53`. The one flag with a visible effect on type-3
/// output: it doubles every string length and switches the copy from
/// [`copy_bytes`] to [`unicodecpy`] (`:669-673`, `:806-825`).
pub(crate) const NTLMFLAG_NEGOTIATE_UNICODE: u32 = 1 << 0;

/// OEM strings are supported in security buffer data -- bit 1.
///
/// `lib/vauth/ntlm.c:57`. Set in the type-1 message this file emits.
pub(crate) const NTLMFLAG_NEGOTIATE_OEM: u32 = 1 << 1;

/// Request that the server's authentication realm be included in the type-2
/// message -- bit 2.
///
/// `lib/vauth/ntlm.c:60`. Set in the type-1 message this file emits.
pub(crate) const NTLMFLAG_REQUEST_TARGET: u32 = 1 << 2;

/// Authenticated communication should carry a digital signature -- bit 4.
///
/// `lib/vauth/ntlm.c:66`, inside `#if DEBUG_ME`.
pub(crate) const NTLMFLAG_NEGOTIATE_SIGN: u32 = 1 << 4;

/// Authenticated communication should be encrypted -- bit 5.
///
/// `lib/vauth/ntlm.c:70`, inside `#if DEBUG_ME`.
pub(crate) const NTLMFLAG_NEGOTIATE_SEAL: u32 = 1 << 5;

/// Datagram authentication is in use -- bit 6.
///
/// `lib/vauth/ntlm.c:74`, inside `#if DEBUG_ME`.
pub(crate) const NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE: u32 = 1 << 6;

/// The LAN Manager session key should be used for signing and sealing --
/// bit 7.
///
/// `lib/vauth/ntlm.c:77`, inside `#if DEBUG_ME`.
pub(crate) const NTLMFLAG_NEGOTIATE_LM_KEY: u32 = 1 << 7;

/// NTLM authentication is in use -- bit 9.
///
/// `lib/vauth/ntlm.c:82`. Set in the type-1 message this file emits. Bit 8
/// has no name in curl and none is invented here.
pub(crate) const NTLMFLAG_NEGOTIATE_NTLM_KEY: u32 = 1 << 9;

/// An anonymous context has been established -- bit 11.
///
/// `lib/vauth/ntlm.c:88`, inside `#if DEBUG_ME`.
pub(crate) const NTLMFLAG_NEGOTIATE_ANONYMOUS: u32 = 1 << 11;

/// A desired authentication realm is included in the type-1 message --
/// bit 12.
///
/// `lib/vauth/ntlm.c:92`, inside `#if DEBUG_ME`. Never set by curl, because
/// the type-1 domain is always empty.
pub(crate) const NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED: u32 = 1 << 12;

/// The client workstation's name is included in the type-1 message --
/// bit 13.
///
/// `lib/vauth/ntlm.c:96`, inside `#if DEBUG_ME`. Never set by curl, for the
/// same reason as bit 12.
pub(crate) const NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED: u32 = 1 << 13;

/// Server and client are on the same machine -- bit 14.
///
/// `lib/vauth/ntlm.c:100`, inside `#if DEBUG_ME`.
pub(crate) const NTLMFLAG_NEGOTIATE_LOCAL_CALL: u32 = 1 << 14;

/// Authenticated communication should be signed with a "dummy" signature --
/// bit 15.
///
/// `lib/vauth/ntlm.c:106`. Set in the type-1 message this file emits.
pub(crate) const NTLMFLAG_NEGOTIATE_ALWAYS_SIGN: u32 = 1 << 15;

/// The target authentication realm is a domain -- bit 16.
///
/// `lib/vauth/ntlm.c:111`, inside `#if DEBUG_ME`. Sent by the server.
pub(crate) const NTLMFLAG_TARGET_TYPE_DOMAIN: u32 = 1 << 16;

/// The target authentication realm is a server -- bit 17.
///
/// `lib/vauth/ntlm.c:115`, inside `#if DEBUG_ME`. Sent by the server.
pub(crate) const NTLMFLAG_TARGET_TYPE_SERVER: u32 = 1 << 17;

/// The target authentication realm is a share -- bit 18.
///
/// `lib/vauth/ntlm.c:119`, inside `#if DEBUG_ME`, where curl's own comment
/// ends *"Usage is unclear."*
pub(crate) const NTLMFLAG_TARGET_TYPE_SHARE: u32 = 1 << 18;

/// The NTLM2 signing and sealing scheme should be used -- bit 19.
///
/// `lib/vauth/ntlm.c:125`. **The branch selector.** Set in the type-1
/// message this file emits; when the server echoes it in the type-2 message,
/// [`create_type3_message`] answers with NTLMv2 (`:608`), and when the
/// server clears it the version-1 branch runs and clears the bit from the
/// emitted type-3 flag word as well (`:662`).
pub(crate) const NTLMFLAG_NEGOTIATE_NTLM2_KEY: u32 = 1 << 19;

/// Unknown purpose -- bit 20.
///
/// `lib/vauth/ntlm.c:130`, inside `#if DEBUG_ME`. The comment is curl's:
/// *"unknown purpose"*.
pub(crate) const NTLMFLAG_REQUEST_INIT_RESPONSE: u32 = 1 << 20;

/// Unknown purpose -- bit 21.
///
/// `lib/vauth/ntlm.c:133`, inside `#if DEBUG_ME`.
pub(crate) const NTLMFLAG_REQUEST_ACCEPT_RESPONSE: u32 = 1 << 21;

/// Unknown purpose -- bit 22.
///
/// `lib/vauth/ntlm.c:136`, inside `#if DEBUG_ME`.
pub(crate) const NTLMFLAG_REQUEST_NONNT_SESSION_KEY: u32 = 1 << 22;

/// The type-2 message includes a Target Information block -- bit 23.
///
/// `lib/vauth/ntlm.c:140`. Read by [`decode_type2_message`], which extracts
/// the block only when this bit is set (`:374`).
pub(crate) const NTLMFLAG_NEGOTIATE_TARGET_INFO: u32 = 1 << 23;

/// 128-bit encryption is supported -- bit 29.
///
/// `lib/vauth/ntlm.c:151`, inside `#if DEBUG_ME`. Bits 24 through 28 have no
/// names in curl, which lists them as "unknown" (`:145-149`).
pub(crate) const NTLMFLAG_NEGOTIATE_128: u32 = 1 << 29;

/// The client will provide an encrypted master key in the type-3 Session Key
/// field -- bit 30.
///
/// `lib/vauth/ntlm.c:154`, inside `#if DEBUG_ME`. curl never does: the
/// session-key security buffer it emits is eight zero bytes.
pub(crate) const NTLMFLAG_NEGOTIATE_KEY_EXCHANGE: u32 = 1 << 30;

/// 56-bit encryption is supported -- bit 31.
///
/// `lib/vauth/ntlm.c:158`, inside `#if DEBUG_ME`. The top bit, which is why
/// the flag word is handled as [`u32`] throughout: C's
/// `unsigned int flags` (`lib/vauth/vauth.h:181`) is 32 bits wide and a
/// narrower type here would drop this flag.
pub(crate) const NTLMFLAG_NEGOTIATE_56: u32 = 1 << 31;

/// The flag word every type-1 message this crate emits carries:
/// `0x0008_8206`.
///
/// `lib/vauth/ntlm.c:480-484` composes it inside the format call:
///
/// ```c
/// LONGQUARTET(NTLMFLAG_NEGOTIATE_OEM |
///             NTLMFLAG_REQUEST_TARGET |
///             NTLMFLAG_NEGOTIATE_NTLM_KEY |
///             NTLMFLAG_NEGOTIATE_NTLM2_KEY |
///             NTLMFLAG_NEGOTIATE_ALWAYS_SIGN)
/// ```
///
/// Bits 1, 2, 9, 15 and 19: `0x2 | 0x4 | 0x200 | 0x8000 | 0x80000`, which is
/// `0x0008_8206` and reaches the wire little-endian as `06 82 08 00`.
///
/// **Fixture-confirmed.** `tests/data/test1008:108` and
/// `tests/data/test1021:118` both expect, literally:
///
/// ```text
/// Proxy-Authorization: NTLM %b64[NTLMSSP%00%01%00%00%00%06%82%08%00%00...]b64%
/// ```
///
/// -- the signature and its NUL, then `01 00 00 00`, then `06 82 08 00`, then
/// twenty zero bytes. Both the value and its little-endian encoding are
/// asserted by test.
pub(crate) const TYPE1_FLAGS: u32 = NTLMFLAG_NEGOTIATE_OEM
    | NTLMFLAG_REQUEST_TARGET
    | NTLMFLAG_NEGOTIATE_NTLM_KEY
    | NTLMFLAG_NEGOTIATE_NTLM2_KEY
    | NTLMFLAG_NEGOTIATE_ALWAYS_SIGN;

/// The flag names, paired with their bits, for [`NtlmFlags`]'s formatter.
///
/// The table `ntlm_print_flags` (`lib/vauth/ntlm.c:162-226`) is written as a
/// chain of twenty-nine `if(flags & X) curl_mfprintf(handle, "X ")`
/// statements inside `#if DEBUG_ME`. As a table it is checkable: a test
/// asserts that every entry's bit is the constant it names, that the entries
/// are in ascending bit order, and that no bit appears twice.
///
/// The five bits curl lists as "unknown" (3, 8, 10, 24 through 28) are
/// absent. The C prints them as `NTLMFLAG_UNKNOWN_n`; reproducing that would
/// mean inventing names for bits nothing defines, and this formatter is a
/// diagnostic aid rather than frozen output -- the whole `DEBUG_ME` block is
/// dead code, so no byte of curl's observable behaviour depends on it.
#[rustfmt::skip]
const FLAG_NAMES: [(u32, &str); 24] = [
    (NTLMFLAG_NEGOTIATE_UNICODE,              "NEGOTIATE_UNICODE"),
    (NTLMFLAG_NEGOTIATE_OEM,                  "NEGOTIATE_OEM"),
    (NTLMFLAG_REQUEST_TARGET,                 "REQUEST_TARGET"),
    (NTLMFLAG_NEGOTIATE_SIGN,                 "NEGOTIATE_SIGN"),
    (NTLMFLAG_NEGOTIATE_SEAL,                 "NEGOTIATE_SEAL"),
    (NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE,       "NEGOTIATE_DATAGRAM_STYLE"),
    (NTLMFLAG_NEGOTIATE_LM_KEY,               "NEGOTIATE_LM_KEY"),
    (NTLMFLAG_NEGOTIATE_NTLM_KEY,             "NEGOTIATE_NTLM_KEY"),
    (NTLMFLAG_NEGOTIATE_ANONYMOUS,            "NEGOTIATE_ANONYMOUS"),
    (NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED,      "NEGOTIATE_DOMAIN_SUPPLIED"),
    (NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED, "NEGOTIATE_WORKSTATION_SUPPLIED"),
    (NTLMFLAG_NEGOTIATE_LOCAL_CALL,           "NEGOTIATE_LOCAL_CALL"),
    (NTLMFLAG_NEGOTIATE_ALWAYS_SIGN,          "NEGOTIATE_ALWAYS_SIGN"),
    (NTLMFLAG_TARGET_TYPE_DOMAIN,             "TARGET_TYPE_DOMAIN"),
    (NTLMFLAG_TARGET_TYPE_SERVER,             "TARGET_TYPE_SERVER"),
    (NTLMFLAG_TARGET_TYPE_SHARE,              "TARGET_TYPE_SHARE"),
    (NTLMFLAG_NEGOTIATE_NTLM2_KEY,            "NEGOTIATE_NTLM2_KEY"),
    (NTLMFLAG_REQUEST_INIT_RESPONSE,          "REQUEST_INIT_RESPONSE"),
    (NTLMFLAG_REQUEST_ACCEPT_RESPONSE,        "REQUEST_ACCEPT_RESPONSE"),
    (NTLMFLAG_REQUEST_NONNT_SESSION_KEY,      "REQUEST_NONNT_SESSION_KEY"),
    (NTLMFLAG_NEGOTIATE_TARGET_INFO,          "NEGOTIATE_TARGET_INFO"),
    (NTLMFLAG_NEGOTIATE_128,                  "NEGOTIATE_128"),
    (NTLMFLAG_NEGOTIATE_KEY_EXCHANGE,         "NEGOTIATE_KEY_EXCHANGE"),
    (NTLMFLAG_NEGOTIATE_56,                   "NEGOTIATE_56"),
];

/// An NTLM flag word, with a formatter that names its bits.
///
/// A newtype rather than a bare [`u32`] so that a flag word cannot be passed
/// where an offset, a length or an [`AuthMask`] is expected. The three
/// vocabularies overlap numerically -- bit 1 means "OEM strings" here and
/// `CURLAUTH_DIGEST` there -- and the type is what keeps them apart.
///
/// [`Copy`] and cheap: this is a wrapped machine word.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(crate) struct NtlmFlags(u32);

impl NtlmFlags {
    /// The empty flag word, which is what `ntlm->flags = 0`
    /// (`lib/vauth/ntlm.c:361`) sets.
    pub(crate) const NONE: Self = Self(0);

    /// Wraps a raw flag word, as read from a type-2 message.
    #[must_use]
    pub(crate) const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw flag word, for the four bytes at type-3 offset 60.
    #[must_use]
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }

    /// Whether **every** bit of `mask` is set.
    ///
    /// C tests a single bit at each of its three decision points
    /// (`lib/vauth/ntlm.c:374`, `:578`, `:608`), so single-bit and
    /// all-bits-of agree there; the stronger reading is chosen because it is
    /// the one that does not silently accept a partial match if a future
    /// caller passes two bits.
    #[must_use]
    pub(crate) const fn contains(self, mask: u32) -> bool {
        self.0 & mask == mask
    }

    /// This flag word with `mask` cleared: C's
    /// `ntlm->flags &= ~(unsigned int)NTLMFLAG_NEGOTIATE_NTLM2_KEY`
    /// (`lib/vauth/ntlm.c:662`).
    ///
    /// The C's cast is what keeps `~` from promoting to a wider signed type;
    /// here the width is the type's and there is nothing to promote.
    #[must_use]
    pub(crate) const fn without(self, mask: u32) -> Self {
        Self(self.0 & !mask)
    }
}

impl fmt::Debug for NtlmFlags {
    /// The hexadecimal word, then the names of the bits that are set.
    ///
    /// Modelled on the C's own diagnostic shape at `lib/vauth/ntlm.c:383`,
    /// `"**** TYPE2 header flags=0x%08.8lx "` followed by
    /// `ntlm_print_flags`, so a reader comparing a Rust trace against a
    /// `DEBUG_ME` build sees the same information in the same order. Nothing
    /// here is a secret: a flag word is sent and received in clear text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NtlmFlags(0x{:08x}", self.0)?;
        for (bit, name) in FLAG_NAMES {
            if self.0 & bit != 0 {
                write!(f, " {name}")?;
            }
        }
        f.write_str(")")
    }
}

// ---------------------------------------------------------------------------
// Little-endian splat helpers. `lib/curl_ntlm_core.h:33-35`.
// ---------------------------------------------------------------------------

/// `SHORTPAIR(x)`: the low sixteen bits of `x`, least significant byte
/// first.
///
/// `lib/curl_ntlm_core.h:33`:
///
/// ```c
/// #define SHORTPAIR(x) ((int)((x) & 0xff)), ((int)(((x) >> 8) & 0xff))
/// ```
///
/// The macro yields **two** `printf` arguments, which is why every security
/// buffer in the C is written as three `SHORTPAIR`s and a pair of literal
/// zeroes rather than as one structure. Here it yields two bytes.
///
/// # Why this is not a cast
///
/// The reachable range is small -- a length or an offset inside a
/// 1024-byte message -- and [`u16::to_le_bytes`] is exact for all of it.
/// The `Err` arm exists for one value the C can reach and this function must
/// not diverge on: `ntresplen` is `48 + target_info_len` with
/// `target_info_len` a `u16` read from the peer, so it can reach 65,583, and
/// the C's macro **truncates** it while the message is formatted -- before
/// the size guard at `lib/vauth/ntlm.c:776-780` rejects it. Reproducing the
/// truncation costs one arm and keeps the two implementations byte-identical
/// on a path neither of them completes.
///
/// Written this way rather than as `(x & 0xffff) as u16` because a masked
/// cast reads as a cast: the reviewer has to verify the mask to know the
/// truncation was intended, where a `match` says so.
fn shortpair(value: usize) -> [u8; 2] {
    match u16::try_from(value) {
        Ok(fits) => fits.to_le_bytes(),
        Err(_) => {
            // C's `& 0xff` and `>> 8 & 0xff` keep the low two bytes and
            // discard the rest. A little-endian view of the wider value has
            // those two bytes at index 0 and 1, so this is the same
            // truncation with no arithmetic of its own.
            let wide = value.to_le_bytes();
            [wide[0], wide[1]]
        }
    }
}

/// `LONGQUARTET(x)`: all thirty-two bits of `x`, least significant byte
/// first.
///
/// `lib/curl_ntlm_core.h:34-35`, four `printf` arguments in the C and four
/// bytes here. The parameter is [`u32`] rather than [`usize`] because every
/// caller has a genuine 32-bit quantity -- a flag word
/// (`lib/vauth/ntlm.c:480`, `:759`) or half a FILETIME
/// (`lib/curl_ntlm_core.c:601-602`) -- so there is nothing to narrow and
/// [`u32::to_le_bytes`] is the whole implementation.
fn longquartet(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// A security buffer: length, allocated size, offset, and the two zeroes
/// that follow it.
///
/// `lib/vauth/ntlm.c:297-303` defines the triplet and every call site adds
/// the same trailing `0x0, 0x0`:
///
/// ```c
/// SHORTPAIR(domlen), SHORTPAIR(domlen), SHORTPAIR(domoff), 0x0, 0x0,
/// ```
///
/// The C writes the pattern out six times in the type-3 header
/// (`:728-757`) and twice in the type-1 (`:485-492`). Writing it once here
/// is not a refactor of behaviour: the eight bytes produced are identical and
/// a test asserts them against the fixture-decoded message.
///
/// The trailing zeroes are the high half of the 32-bit offset. C spells them
/// as literals because `SHORTPAIR` only yields two bytes, so an offset above
/// 65,535 would be silently lost -- which no NTLM message can reach, since
/// the whole message is bounded by [`NTLM_BUFSIZE`].
///
/// `allocated` is separate from `length` because the layout has two fields,
/// even though every curl call site passes the same value to both.
fn security_buffer(length: usize, offset: usize) -> [u8; 8] {
    let len = shortpair(length);
    let allocated = shortpair(length);
    let off = shortpair(offset);
    [
        len[0],
        len[1],
        allocated[0],
        allocated[1],
        off[0],
        off[1],
        0,
        0,
    ]
}

/// A little-endian `u16` read from the first two bytes of `bytes`.
///
/// `Curl_read16_le` (`lib/curl_endian.c`), the reader
/// `lib/vauth/ntlm.c:266` uses for the target-info length. Takes an array
/// rather than a slice so the length is proved at the call site, where the
/// bound on the peer's message has just been checked, rather than here where
/// a failure would have no honest answer.
fn read16_le(bytes: [u8; 2]) -> u16 {
    u16::from_le_bytes(bytes)
}

/// A little-endian `u32` read from the first four bytes of `bytes`.
///
/// `Curl_read32_le` (`lib/curl_endian.c`), used at `lib/vauth/ntlm.c:267`
/// for the target-info offset and at `:371` for the flag word. See
/// [`read16_le`] on why the parameter is an array.
fn read32_le(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

// ---------------------------------------------------------------------------
// String widening. `lib/vauth/ntlm.c:394-403` and
// `lib/curl_ntlm_core.c:396-404`, which are the same function twice.
// ---------------------------------------------------------------------------

/// Widens `src` by interleaving a zero after every byte.
///
/// The C has this function twice, identically, once per translation unit:
/// `unicodecpy` (`lib/vauth/ntlm.c:396-403`) and `ascii_to_unicode_le`
/// (`lib/curl_ntlm_core.c:396-404`). Both bodies are:
///
/// ```c
/// for(i = 0; i < srclen; i++) {
///   dest[2 * i] = (unsigned char)src[i];
///   dest[2 * i + 1] = '\0';
/// }
/// ```
///
/// # This is not UTF-16, and must not be replaced by UTF-16
///
/// It is **naive byte widening**. A source byte at or above `0x80` is copied
/// through unchanged and paired with a zero, which encodes the Latin-1 code
/// point of that byte rather than the character the byte meant in whatever
/// encoding it arrived in. A correct UTF-16 encoder would emit different
/// bytes for exactly those inputs -- two units for a non-ASCII character, or
/// a replacement -- and different bytes are a different NTLM message: a
/// different NT hash, a different response, and a rejected login against
/// every server that agrees with curl.
///
/// So the naivety is the contract. A test asserts that `0xC3` widens to
/// `C3 00` and not to anything a UTF-16 encoder would produce.
///
/// The two names are kept as one function because the two C bodies are
/// byte-identical and a reader checking either citation lands here.
fn unicodecpy(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len().saturating_mul(2));
    for &byte in src {
        out.push(byte);
        out.push(0);
    }
    out
}

/// Widens `src` after folding ASCII lower case to upper case.
///
/// `ascii_uppercase_to_unicode_le` (`lib/curl_ntlm_core.c:489-497`):
/// [`unicodecpy`] with `Curl_raw_toupper` applied to each byte. The fold is
/// ASCII-only and leaves `0x80..=0xFF` untouched, which is exactly what
/// [`raw_toupper`] does.
///
/// Its one caller is [`mk_ntlmv2_hash`], and **only for the username**. See
/// there for why the asymmetry with the domain matters.
fn ascii_uppercase_to_unicode_le(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len().saturating_mul(2));
    for &byte in src {
        out.push(raw_toupper(byte));
        out.push(0);
    }
    out
}

/// Copies `src` unchanged: the `memcpy` arm of the type-3 string writes.
///
/// `lib/vauth/ntlm.c:806-825` chooses between `unicodecpy` and `memcpy` on
/// the UNICODE flag. Naming the second arm gives the call sites one shape
/// instead of two and keeps the choice visible at the branch rather than in
/// the middle of an append.
fn copy_bytes(src: &[u8]) -> Vec<u8> {
    src.to_vec()
}

/// Skips leading spaces and tabs.
///
/// The one line of `curlx_str_passblanks` that `lib/http_ntlm.c:69` needs,
/// transcribed locally: `crate::util::strparse::str_passblanks` is the
/// crate-wide form and behaves identically, and `util/strparse.rs` is not
/// among the modules this file declares a dependency on. The predicate is
/// `ISBLANK`, which `lib/curl_ctype.h` defines as space or horizontal tab
/// and **not** as general whitespace -- so this is deliberately not
/// `trim_ascii_start`, which would also eat a newline or a carriage return
/// and would change which challenges parse.
fn pass_blanks(cursor: &[u8]) -> &[u8] {
    let mut rest = cursor;
    while let Some((&first, tail)) = rest.split_first() {
        if first != b' ' && first != b'\t' {
            break;
        }
        rest = tail;
    }
    rest
}

// ---------------------------------------------------------------------------
// State. `struct ntlmdata` (`lib/vauth/vauth.h:163-186`, non-SSPI arm) and
// `curlntlm` (`lib/urldata.h:312-318`).
// ---------------------------------------------------------------------------

/// What a connection remembers between the type-2 and type-3 messages.
///
/// The non-SSPI arm of `struct ntlmdata` (`lib/vauth/vauth.h:180-185`):
///
/// ```c
/// unsigned int flags;
/// unsigned char nonce[8];
/// unsigned int target_info_len;
/// void *target_info; /* TargetInfo received in the NTLM type-2 message */
/// ```
///
/// Three fields become three, with one shape change: the `void *` and its
/// separate length become one `Option<Vec<u8>>`, so the pair cannot disagree
/// and the cast at every use disappears. `None` and `Some(empty)` are
/// distinguishable and the distinction is used -- see
/// [`Self::target_info_len`], which reproduces a C subtlety that depends on
/// it.
///
/// Every SSPI field is excluded; the module documentation lists them.
///
/// # `Default` is the `calloc` of `Curl_auth_ntlm_get`
///
/// `lib/vauth/vauth.c:160-176` allocates the structure with `calloc` on
/// first use, so a fresh instance is all zeroes: no flags, a zero challenge,
/// no target info. `#[derive(Default)]` gives exactly that, which is why
/// [`MechanismSlots::get_or_default`] is the right accessor for it.
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct NtlmData {
    /// The flag word from the type-2 message, or [`NtlmFlags::NONE`].
    flags: NtlmFlags,
    /// The server challenge from type-2 offset 24, eight bytes.
    ///
    /// Called `nonce` by C, which is the name used throughout so that the
    /// citations line up, though it is a challenge rather than a nonce in the
    /// cryptographic sense: the server picks it and the client never repeats
    /// one.
    nonce: [u8; CHALLENGE_LEN],
    /// The Target Information block, when the server sent one.
    ///
    /// `None` when no block arrived; `Some` with the exact bytes when one
    /// did. C's `target_info_len` is not a separate field here because
    /// [`Vec::len`] is that field, and two sources of truth for one length is
    /// how a buffer over-read is written.
    target_info: Option<Vec<u8>>,
}

impl NtlmData {
    /// A fresh instance: the `calloc`ed state of `Curl_auth_ntlm_get`.
    #[must_use]
    #[allow(dead_code)] // Reached by this file's tests and by `NtlmConnection`.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The flag word most recently decoded, or [`NtlmFlags::NONE`].
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) const fn flags(&self) -> NtlmFlags {
        self.flags
    }

    /// The server challenge, eight bytes.
    #[must_use]
    pub(crate) const fn nonce(&self) -> &[u8; CHALLENGE_LEN] {
        &self.nonce
    }

    /// The Target Information block, or an empty slice when none arrived.
    ///
    /// An empty slice rather than an `Option` because every consumer wants
    /// the bytes and the length: `lib/curl_ntlm_core.c:605-606` guards the
    /// copy on `if(ntlm->target_info_len)` and then copies that many bytes,
    /// which is what a slice expresses without a branch.
    #[must_use]
    pub(crate) fn target_info(&self) -> &[u8] {
        match &self.target_info {
            Some(bytes) => bytes,
            None => &[],
        }
    }

    /// The length C's `target_info_len` field holds.
    ///
    /// Identical to `self.target_info().len()` and named separately because
    /// the C field is what [`mk_ntlmv2_resp`]'s size arithmetic
    /// (`NTLMv2_BLOB_LEN`, `lib/curl_ntlm_core.c:437`) is written in terms
    /// of, and a reader checking that arithmetic should find the same name.
    #[must_use]
    pub(crate) fn target_info_len(&self) -> usize {
        self.target_info().len()
    }

    /// Discards the Target Information block: `Curl_auth_cleanup_ntlm`.
    ///
    /// `lib/vauth/ntlm.c:850-857`, in full:
    ///
    /// ```c
    /// void Curl_auth_cleanup_ntlm(struct ntlmdata *ntlm)
    /// {
    ///   Curl_safefree(ntlm->target_info);
    ///   ntlm->target_info_len = 0;
    /// }
    /// ```
    ///
    /// # It clears the target info and nothing else, deliberately
    ///
    /// `flags` and `nonce` **survive** a cleanup. That is not an oversight in
    /// the C and it is load-bearing: [`create_type1_message`] calls cleanup
    /// before composing its message (`:462`, "Clean up any former leftovers
    /// and initialise to defaults"), and if that call also reset the flag
    /// word then a restarted handshake would lose the state a later type-2
    /// decode overwrites anyway -- while a caller that reads `flags` between
    /// the two would see a different value than the C shows it. Reproducing
    /// the narrow clear keeps the observable sequence identical.
    ///
    /// [`create_type3_message`] calls this on **both** its success and its
    /// error paths (`:832-835`), so the block is never carried into a second
    /// type-3 message.
    pub(crate) fn cleanup(&mut self) {
        self.target_info = None;
    }
}

impl fmt::Debug for NtlmData {
    /// Prints the flag word, the challenge, and the **length** of the target
    /// info.
    ///
    /// Hand-written rather than derived. Nothing in this structure is a
    /// credential -- the flag word and the challenge both cross the wire in
    /// clear text, which is what makes them safe to print -- but the target
    /// info is an attacker-supplied blob of unbounded length, and a derived
    /// formatter would splice all of it into a diagnostic. Its length is the
    /// part a reader needs, and it is the part the C's own arithmetic is
    /// written in terms of.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtlmData")
            .field("flags", &self.flags)
            .field("nonce", &HexBytes(&self.nonce))
            .field("target_info_len", &self.target_info_len())
            .finish()
    }
}

/// Renders a byte slice as lowercase hexadecimal for a formatter.
///
/// The successor of `ntlm_print_hex` (`lib/vauth/ntlm.c:228-237`), which is
/// inside `#if DEBUG_ME` and prints `0x` followed by `%02.2x` per byte. Used
/// only for values that are already public: a server challenge and, in
/// tests, a message body. It is deliberately **not** implemented for
/// [`LmHash`] or [`NtHash`].
struct HexBytes<'a>(&'a [u8]);

impl fmt::Debug for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Where the HTTP exchange has reached, on one connection and one side.
///
/// `typedef enum { ... } curlntlm` -- `lib/urldata.h:312-318`, in this exact
/// order, which the C depends on twice: `lib/http_ntlm.c:99` tests
/// `*state >= NTLMSTATE_TYPE1`, and the `switch` at `:195` relies on
/// `NTLMSTATE_NONE` reaching `default`.
///
/// The ordering is therefore reproduced as [`PartialOrd`] and the comparison
/// is written as the C writes it. `NTLMSTATE_LAST` is a real state and not a
/// count sentinel -- `:238` has a `case` for it -- so all five variants are
/// modelled and none is a placeholder.
///
/// # Per connection, and separately per side
///
/// C stores two of these on the connection: `conn->http_ntlm_state` and
/// `conn->proxy_ntlm_state` (`lib/urldata.h:683-684`). That is
/// [`super::StateScope::Connection`], and the contrast with Digest -- whose
/// state is per **transfer** on the easy handle -- is visible behaviour: an
/// NTLM handshake is bound to the TCP connection and is meaningless across a
/// new one, which is also why NTLM forces HTTP/1.1.
/// [`NtlmConnection`] holds the pair.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum NtlmState {
    /// `NTLMSTATE_NONE`: nothing has happened yet. The `calloc`ed value, and
    /// so the [`Default`].
    #[default]
    None,
    /// `NTLMSTATE_TYPE1`: a type-1 message is to be sent.
    Type1,
    /// `NTLMSTATE_TYPE2`: a type-2 message has been received and decoded.
    Type2,
    /// `NTLMSTATE_TYPE3`: a type-3 message has been sent.
    Type3,
    /// `NTLMSTATE_LAST`: the connection is authenticated and must send no
    /// further NTLM header.
    Last,
}

/// The NTLM state of one connection: two exchange states and two data
/// blocks.
///
/// Supersedes four things at once. The two `curlntlm` fields
/// (`lib/urldata.h:683-684`) become [`Self::state`] and
/// [`Self::state_mut`]; the two string-keyed connection metadata entries
/// that `Curl_auth_ntlm_get` and `Curl_auth_ntlm_remove`
/// (`lib/vauth/vauth.c:160-176`) manage become a
/// [`MechanismSlots<NtlmData>`].
///
/// # The metadata keys are not reproduced
///
/// `lib/vauth/vauth.h:159,161` spells them `"meta:auth:ntml:conn"` and
/// `"meta:auth:ntml-proxy:conn"` -- `ntml`, an upstream typo. It is recorded
/// so a future reader knows it was seen rather than missed, and it is
/// harmless: the keys are internal to one process, never on the wire, never
/// in the ABI and never in a file format, so nothing observable depends on
/// their spelling. What replaces them is a typed field per side, which also
/// removes `ntlm_conn_dtor` -- the destructor becomes ordinary Rust
/// ownership.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NtlmConnection {
    /// `conn->http_ntlm_state`.
    origin_state: NtlmState,
    /// `conn->proxy_ntlm_state`.
    proxy_state: NtlmState,
    /// The two `struct ntlmdata` metadata entries.
    data: MechanismSlots<NtlmData>,
}

impl NtlmConnection {
    /// A connection that has not yet begun an NTLM exchange on either side.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::conn`, not yet landed.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The exchange state for one side: C's
    /// `proxy ? conn->proxy_ntlm_state : conn->http_ntlm_state`.
    #[must_use]
    pub(crate) const fn state(&self, proxy: bool) -> NtlmState {
        if proxy {
            self.proxy_state
        } else {
            self.origin_state
        }
    }

    /// The exchange state for one side, mutably.
    ///
    /// C takes the address of the field once, at
    /// `lib/http_ntlm.c:61` and `:148`/`:161`, and then writes through the
    /// pointer; this is that pointer.
    pub(crate) fn state_mut(&mut self, proxy: bool) -> &mut NtlmState {
        if proxy {
            &mut self.proxy_state
        } else {
            &mut self.origin_state
        }
    }

    /// The [`NtlmData`] for one side, creating it if absent:
    /// `Curl_auth_ntlm_get(conn, proxy)`.
    ///
    /// C returns `NULL` when either the `calloc` or the metadata insertion
    /// fails, and both `Curl_input_ntlm` (`lib/http_ntlm.c:65-66`) and
    /// `Curl_output_ntlm` (`:165-166`) raise `CURLE_OUT_OF_MEMORY` on it.
    /// Neither can fail here, so this returns a reference rather than an
    /// `Option` and that error has no path to reach -- which is why neither
    /// [`input_ntlm`] nor [`output_ntlm`] contains it.
    pub(crate) fn data_mut(&mut self, proxy: bool) -> &mut NtlmData {
        self.data.get_or_default(proxy)
    }

    /// The [`NtlmData`] for one side, if the exchange has created it.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn peek(&self, proxy: bool) -> Option<&NtlmData> {
        self.data.peek(proxy)
    }

    /// Discards one side's [`NtlmData`]: `Curl_auth_ntlm_remove(conn, proxy)`
    /// (`lib/vauth/vauth.c:171-176`).
    ///
    /// The exchange state is **not** touched. `Curl_input_ntlm` calls the
    /// removal and then assigns the state explicitly, differently in each of
    /// its two branches (`lib/http_ntlm.c:89-97`), so folding a state change
    /// in here would produce the wrong one for one of them.
    pub(crate) fn remove(&mut self, proxy: bool) {
        // The taken value is dropped at the end of this statement, which is
        // where C's `Curl_conn_meta_remove` runs the destructor.
        self.data.remove(proxy);
    }
}

/// The two `data->info.*authpicked` fields.
///
/// `data->info.httpauthpicked` and `data->info.proxyauthpicked`, which
/// `Curl_output_ntlm`'s `NTLMSTATE_LAST` arm writes directly
/// (`lib/http_ntlm.c:241-244`) and which the application reads back through
/// `CURLINFO_HTTPAUTH_USED` and `CURLINFO_PROXYAUTH_USED`.
///
/// A pair here, rather than in `easy/getinfo.rs` where `data->info`
/// ultimately belongs, because that module has not landed and this file has a
/// writer that must not be dropped: the `LAST` arm emits **no header**, so
/// this field is the only trace it leaves, and losing it would make
/// `CURLINFO_HTTPAUTH_USED` report nothing on an already-authenticated NTLM
/// connection. `super::AuthActOutcome` carries the same two values out of
/// arbitration under the names `host_picked` and `proxy_picked`; this is the
/// same information written from the other of C's two writers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuthPickedInfo {
    /// `data->info.httpauthpicked`.
    pub(crate) origin: Option<AuthMask>,
    /// `data->info.proxyauthpicked`.
    pub(crate) proxy: Option<AuthMask>,
}

impl AuthPickedInfo {
    /// Nothing picked on either side: the `calloc`ed `data->info`.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::easy::getinfo`, not yet landed.
    pub(crate) const fn new() -> Self {
        Self {
            origin: None,
            proxy: None,
        }
    }

    /// Records `mask` on one side, as C's `if(proxy) ... else ...` does.
    ///
    /// The branch stays inside this function rather than at the call site so
    /// that the two fields cannot be swapped by a caller reading
    /// `lib/http_ntlm.c:241-244` from memory.
    pub(crate) fn set(&mut self, proxy: bool, mask: AuthMask) {
        if proxy {
            self.proxy = Some(mask);
        } else {
            self.origin = Some(mask);
        }
    }

    /// What was picked on one side.
    #[must_use]
    #[allow(dead_code)] // Consumer is `crate::easy::getinfo`, not yet landed.
    pub(crate) const fn get(&self, proxy: bool) -> Option<AuthMask> {
        if proxy {
            self.proxy
        } else {
            self.origin
        }
    }
}

// ---------------------------------------------------------------------------
// Cryptographic primitives. `lib/curl_ntlm_core.c`, all six DES backends
// collapsed into one.
// ---------------------------------------------------------------------------

/// A 21-byte key buffer: three 56-bit DES keys laid end to end.
///
/// The shape both `Curl_ntlm_core_mk_lm_hash` and
/// `Curl_ntlm_core_mk_nt_hash` fill and `Curl_ntlm_core_lm_resp` consumes
/// (`lib/curl_ntlm_core.c:308-310`, `:353`, `:410`). A newtype rather than a
/// bare array for one reason that matters more than type safety: **it has a
/// formatter that prints nothing.**
///
/// # This is password-equivalent material
///
/// An LM or NT hash is not a password, but it is exactly what an offline
/// attack needs and exactly what a pass-the-hash attack replays. A derived
/// [`fmt::Debug`] would splice it into any diagnostic that ever prints a
/// structure containing one, which is how a secret reaches a log without
/// anybody deciding that it should. curl never prints these, and neither does
/// this: [`fmt::Debug`] is hand-written and emits
/// [`REDACTED_PLACEHOLDER`].
///
/// The same reasoning covers `Clone` -- present, because the type is a small
/// array and a caller needs to key two responses from one hash -- and the
/// absence of `Display`, `Deref` and any accessor returning the raw bytes to
/// arbitrary callers. [`Self::key`] hands out one seven-byte DES key at a
/// time, which is what the algorithm needs and no more.
#[derive(Clone)]
pub(crate) struct HashKeys([u8; HASH_KEY_LEN]);

impl HashKeys {
    /// The all-zero buffer, which every constructor starts from.
    ///
    /// C declares `unsigned char ntbuffer[0x18]` uninitialised and then
    /// writes 16 bytes of digest followed by
    /// `memset(buffer + 16, 0, 21 - 16)` (`lib/curl_ntlm_core.c:390`,
    /// `:427`). Starting from zero makes the tail zeroing structural instead
    /// of a step that can be forgotten -- and the tail is not decoration: it
    /// is the third DES key, so a stale byte there changes the last eight
    /// bytes of every response.
    const fn zeroed() -> Self {
        Self([0; HASH_KEY_LEN])
    }

    /// The 16-byte digest half, which every constructor writes.
    fn set_digest(&mut self, digest: &[u8; 16]) {
        self.0[..16].copy_from_slice(digest);
    }

    /// One of the three 56-bit DES keys: `keys`, `keys + 7` or `keys + 14`.
    ///
    /// `index` is 0, 1 or 2. Panicking is impossible for those values and the
    /// only caller is [`lm_resp`], which passes each of them literally, so
    /// the bound is a compile-time-visible constant rather than an input.
    fn key(&self, index: usize) -> [u8; 7] {
        let start = index * 7;
        let mut key = [0u8; 7];
        key.copy_from_slice(&self.0[start..start + 7]);
        key
    }
}

impl fmt::Debug for HashKeys {
    /// Prints a placeholder. See the type's documentation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HashKeys")
            .field(&REDACTED_PLACEHOLDER)
            .finish()
    }
}

/// An LM hash: `Curl_ntlm_core_mk_lm_hash`'s 21-byte output.
///
/// Distinct from [`NtHash`] so the two cannot be swapped. They are the same
/// shape and are keyed into the same function, and swapping them produces a
/// message that is well formed, is accepted by nothing, and reports no error
/// -- which is the class of defect a newtype exists to prevent.
pub(crate) type LmHash = HashKeys;

/// An NT hash: `Curl_ntlm_core_mk_nt_hash`'s 21-byte output.
///
/// An alias of the same type as [`LmHash`] rather than a second newtype. The
/// two are genuinely interchangeable as *inputs to DES* -- `lm_resp` takes
/// either, which is the whole point of its "takes a 21 byte array" comment
/// (`lib/curl_ntlm_core.c:308`) -- so a distinct type would force a
/// conversion that says nothing. What matters is the formatter, and both
/// share it.
pub(crate) type NtHash = HashKeys;

/// Applies odd parity to all eight bytes.
///
/// `curl_des_set_odd_parity` (`lib/curl_ntlm_core.c:142-158`), which curl
/// itself describes as a port of the Java `oddParity()` at
/// davenport.sourceforge.net and compiles only when the crypto backend has no
/// version of its own (`#ifdef USE_CURL_DES_SET_ODD_PARITY`, enabled for
/// GnuTLS, OS/400 and Windows). The OpenSSL arm calls
/// `DES_set_odd_parity` instead (`:189`), which does the same thing.
///
/// The rule is C's, transcribed: exclusive-or bits 7 down to 1; if the result
/// is zero the byte has an even number of set bits among them, so bit 0 is
/// **set** to make the total odd; otherwise bit 0 is **cleared**.
///
/// # It has no effect on the output, and is implemented anyway
///
/// DES ignores bit 0 of every key byte -- the key schedule discards it -- so
/// parity adjustment cannot change a single bit of ciphertext, and
/// `des 0.8.1` neither adjusts parity nor rejects a weak key, so nothing
/// downstream requires it. It is here because the C does it, at a point where
/// the derived key is observable to anybody stepping through either
/// implementation, and a reader auditing the two against each other must find
/// the same 64-bit key in both. Removing it would be a silent divergence in
/// an intermediate value for no gain.
#[rustfmt::skip]
fn set_odd_parity(bytes: &mut [u8; 8]) {
    for byte in bytes.iter_mut() {
        let b = *byte;
        let folded = (b >> 7) ^ (b >> 6) ^ (b >> 5) ^ (b >> 4)
                   ^ (b >> 3) ^ (b >> 2) ^ (b >> 1);
        if folded & 0x01 == 0 {
            *byte = b | 0x01;
        } else {
            *byte = b & 0xfe;
        }
    }
}

/// Spreads a 56-bit key over eight bytes, then sets odd parity.
///
/// `extend_key_56_to_64` (`lib/curl_ntlm_core.c:164-174`) followed by the
/// parity call every `setup_des_key` arm makes (`:186-192` for OpenSSL,
/// `:199-206` for GnuTLS, and the same shape in the remaining four). The two
/// are one function here because no caller wants the unadjusted form.
///
/// The shift chain is transcribed literally, in C's order:
///
/// ```c
/// key[0] = (char)key_56[0];
/// key[1] = (char)(((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1));
/// key[2] = (char)(((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2));
/// key[3] = (char)(((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3));
/// key[4] = (char)(((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4));
/// key[5] = (char)(((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5));
/// key[6] = (char)(((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6));
/// key[7] = (char) ((key_56[6] << 1) & 0xFF);
/// ```
///
/// C's `& 0xFF` is what keeps the left shift inside a byte after integer
/// promotion. Rust's `u8 << n` is already byte-wide -- and, being a shift
/// rather than an arithmetic operation, discards the bits that leave the top
/// rather than overflowing -- so the mask is implicit. It is written out
/// anyway, for the same reason the parity is applied: a reader diffing the
/// two implementations should find the same eight expressions.
///
/// `#[rustfmt::skip]` keeps the chain aligned. Reflowed to 80 columns it
/// becomes unreviewable against the C.
///
/// `clippy::identity_op` fires on each `& 0xFF` and is correct that the mask
/// changes nothing: a `u8` shift is already byte-wide. The mask is kept
/// regardless, and the lint allowed at this one item, because the whole value
/// of this function is that it can be diffed against
/// `lib/curl_ntlm_core.c:166-173` line for line -- the same trade
/// `crate::util::parsedate` records at its own transcribed arithmetic.
#[rustfmt::skip]
#[allow(clippy::identity_op)]
fn extend_key_56_to_64(key_56: &[u8; 7]) -> [u8; 8] {
    let k = key_56;
    let mut key: [u8; 8] = [
        k[0],
        ((k[0] << 7) & 0xFF) | (k[1] >> 1),
        ((k[1] << 6) & 0xFF) | (k[2] >> 2),
        ((k[2] << 5) & 0xFF) | (k[3] >> 3),
        ((k[3] << 4) & 0xFF) | (k[4] >> 4),
        ((k[4] << 3) & 0xFF) | (k[5] >> 5),
        ((k[5] << 2) & 0xFF) | (k[6] >> 6),
         (k[6] << 1) & 0xFF,
    ];

    // Every `setup_des_key` arm adjusts parity before installing the key.
    set_odd_parity(&mut key);

    key
}

/// One DES-ECB encryption of one eight-byte block under a 56-bit key.
///
/// The single operation all six C backends provide and the only cryptographic
/// primitive NTLMv1 needs. Compare the arms that collapse into it:
/// `DES_set_key_unchecked` plus `DES_ecb_encrypt(..., DES_ENCRYPT)` for
/// OpenSSL and wolfSSL (`lib/curl_ntlm_core.c:181-193`, `:316-329`),
/// `des_set_key` plus `des_encrypt` for GnuTLS/nettle (`:197-206`,
/// `:330-337`), and an `encrypt_des` helper for mbedTLS, OS/400 and Windows
/// (`:338-342`).
///
/// Infallible and free of `unsafe`. `des 0.8.1` takes its key as a
/// fixed-size array, so the key length is proved by the type and
/// `new_from_slice`'s `Result` never arises; `encrypt_block` works in place
/// on an eight-byte block, which is why the plaintext is copied first.
fn des_ecb_encrypt(key_56: &[u8; 7], plaintext: &[u8; 8]) -> [u8; 8] {
    let key = extend_key_56_to_64(key_56);
    let cipher = Des::new(&key.into());

    let mut block = *plaintext;
    cipher.encrypt_block((&mut block).into());

    block
}

/// The 24-byte response: the same plaintext encrypted under all three keys.
///
/// `Curl_ntlm_core_lm_resp` (`lib/curl_ntlm_core.c:312-348`), whose own
/// comment is the specification: *"takes a 21 byte array and treats it as 3
/// 56-bit DES keys. The 8 byte plaintext is encrypted with each key and the
/// resulting 24 bytes are stored in the results array."*
///
/// Note what it is **not**: three chained encryptions, and not Triple DES.
/// The same eight bytes go into each of the three independently, and the
/// three ciphertexts are concatenated. That is why `des 0.8.1`'s `TdesEde3`
/// is not used here even though it exists -- it would compute something
/// entirely different.
///
/// Called twice per NTLMv1 type-3 message: once keyed by the NT hash for the
/// NT response and once by the LM hash for the LM response
/// (`lib/vauth/ntlm.c:655`, `:661`).
pub(crate) fn lm_resp(
    keys: &HashKeys,
    plaintext: &[u8; CHALLENGE_LEN],
) -> [u8; RESPONSE_LEN] {
    let mut out = [0u8; RESPONSE_LEN];

    out[0..8].copy_from_slice(&des_ecb_encrypt(&keys.key(0), plaintext));
    out[8..16].copy_from_slice(&des_ecb_encrypt(&keys.key(1), plaintext));
    out[16..24].copy_from_slice(&des_ecb_encrypt(&keys.key(2), plaintext));

    out
}

/// The LM hash of `password`.
///
/// `Curl_ntlm_core_mk_lm_hash` (`lib/curl_ntlm_core.c:353-394`). Four steps,
/// each of which is a place an implementation goes wrong:
///
/// 1. **Truncate to fourteen bytes**, `CURLMIN(strlen(password), 14)`
///    (`:360`). Not an error -- the algorithm has room for two 56-bit keys
///    and no more, so a longer password is silently shortened.
/// 2. **Fold to upper case**, `Curl_strntoupper((char *)pw, password, len)`
///    (`:362`). LM is case-insensitive; NT is not. [`mk_nt_hash`] does
///    **not** do this, and the asymmetry is the single most-copied bug in
///    NTLM implementations.
/// 3. **Zero-pad to fourteen**, `memset(&pw[len], 0, 14 - len)` (`:363`).
///    The padding is part of the key material, so a shorter password is not
///    a shorter key.
/// 4. **Encrypt the magic plaintext twice**, under `pw[0..7]` and
///    `pw[7..14]`, into bytes 0 through 15 (`:371-377`). Note the direction:
///    the password is the *key* and [`LM_HASH_MAGIC`] is the *plaintext*.
///    Reversing them is the second-most-copied bug.
///
/// Bytes 16 through 20 are zero, from [`HashKeys::zeroed`], which is C's
/// `memset(lmbuffer + 16, 0, 21 - 16)` at `:390`.
///
/// Infallible where the C returns `CURLcode`: its every path returns
/// `CURLE_OK` (`:393` is the only `return`), because nothing in it allocates.
///
/// The password arrives as bytes rather than as text because it reaches curl
/// from a URL, an option or a `.netrc` file and is not required to be UTF-8.
pub(crate) fn mk_lm_hash(password: &[u8]) -> LmHash {
    // `unsigned char pw[14]` (`:356`), pre-zeroed so that step 3 above is
    // structural: what `strntoupper` does not write stays zero.
    let mut pw = [0u8; LM_PASSWORD_MAX];

    // `Curl_strntoupper` copies `min(dest.len(), src.len())` folded bytes,
    // which is `CURLMIN(strlen(password), 14)` with the truncation expressed
    // by the destination rather than by a separate `len`.
    let written = strntoupper(&mut pw, password);
    debug_assert_eq!(written, password.len().min(LM_PASSWORD_MAX));

    let mut hash = HashKeys::zeroed();
    let mut digest = [0u8; 16];

    // Two DES encryptions OF THE MAGIC, keyed by the two halves of the
    // padded password.
    let (first, second) = pw.split_at(7);
    let mut key = [0u8; 7];

    key.copy_from_slice(first);
    digest[0..8].copy_from_slice(&des_ecb_encrypt(&key, &LM_HASH_MAGIC));

    key.copy_from_slice(second);
    digest[8..16].copy_from_slice(&des_ecb_encrypt(&key, &LM_HASH_MAGIC));

    hash.set_digest(&digest);
    hash
}

/// The NT hash of `password`: MD4 over the widened password.
///
/// `Curl_ntlm_core_mk_nt_hash` (`lib/curl_ntlm_core.c:410-432`):
///
/// 1. **Reject an absurd length.** `if(len > SIZE_MAX / 2)` (`:416`) guards
///    the `len * 2` allocation that follows and returns
///    `CURLE_OUT_OF_MEMORY`. Reproduced with the same threshold and the same
///    code, even though the allocation it protects is now a [`Vec`]: it is a
///    reachable return value of a public C entry point.
/// 2. **Widen, without folding case.** `ascii_to_unicode_le(pw, password,
///    len)` (`:422`) -- [`unicodecpy`], no upper-casing. Contrast
///    [`mk_lm_hash`] step 2.
/// 3. **MD4 the widened bytes.** `Curl_md4it(ntbuffer, pw, 2 * len)`
///    (`:425`). This is **the only MD4 call site in the entire codebase**,
///    which is why [`mod@crate::crypto::md4`] offers a one-shot function and no
///    streaming context: nothing needs one.
/// 4. **Zero bytes 16 through 20**, `memset(ntbuffer + 16, 0, 21 - 16)`
///    (`:427`) -- and note the C does this only `if(!result)`, which
///    [`HashKeys::zeroed`] makes unconditional and therefore correct on both
///    paths.
///
/// # Errors
///
/// [`CURLcode::OutOfMemory`] when `password` is longer than half the address
/// space, which is C's own guard and not an invented one.
pub(crate) fn mk_nt_hash(password: &[u8]) -> Result<NtHash, CURLcode> {
    // `if(len > SIZE_MAX / 2) return CURLE_OUT_OF_MEMORY;` -- avoid the
    // overflow of `len * 2`. Unreachable in practice; transcribed because it
    // is an observable return value.
    if password.len() > usize::MAX / 2 {
        return Err(CURLcode::OutOfMemory);
    }

    let widened = unicodecpy(password);

    let mut hash = HashKeys::zeroed();
    hash.set_digest(&md4(&widened));

    Ok(hash)
}

/// The NTLMv2 hash: HMAC-MD5 of the widened identity, keyed by the NT hash.
///
/// `Curl_ntlm_core_mk_ntlmv2_hash` (`lib/curl_ntlm_core.c:502-529`), whose
/// comment states it exactly: *"This creates the NTLMv2 hash by using NTLM
/// hash as the key and Unicode (uppercase UserName + Domain) as the data"*.
///
/// # The username is upper-cased and the domain is not
///
/// `:521-522`, and this asymmetry is the classic NTLMv2 implementation bug:
///
/// ```c
/// ascii_uppercase_to_unicode_le(identity, user, userlen);
/// ascii_to_unicode_le(identity + (userlen << 1), domain, domlen);
/// ```
///
/// Two different functions, one line apart. Folding the domain as well, or
/// neither, produces a hash that is wrong in a way no error message reports:
/// the server simply denies the login. It is transcribed literally and
/// asserted by test.
///
/// The key is the NT hash's **first sixteen bytes** -- `ntlmhash, 16` at
/// `:524`, not the 21-byte buffer -- because the five trailing zeroes are
/// DES key padding and are not part of the digest.
///
/// # Errors
///
/// [`CURLcode::OutOfMemory`] when either the username or the domain exceeds
/// [`CURL_MAX_INPUT_LENGTH`] (`:512-513`). Note the code: the C returns
/// out-of-memory here and **not** `CURLE_TOO_LARGE`, even though the
/// condition is a length check, and the code a caller observes is frozen
/// output.
pub(crate) fn mk_ntlmv2_hash(
    user: &[u8],
    domain: &[u8],
    nt_hash: &NtHash,
) -> Result<[u8; 16], CURLcode> {
    if user.len() > CURL_MAX_INPUT_LENGTH
        || domain.len() > CURL_MAX_INPUT_LENGTH
    {
        return Err(CURLcode::OutOfMemory);
    }

    // `identity_len = (userlen + domlen) * 2` (`:515`). The two widened
    // halves are concatenated, upper-cased user first.
    let mut identity = ascii_uppercase_to_unicode_le(user);
    identity.extend_from_slice(&unicodecpy(domain));
    debug_assert_eq!(identity.len(), (user.len() + domain.len()) * 2);

    // `Curl_hmacit(&Curl_HMAC_MD5, ntlmhash, 16, identity, identity_len, ...)`
    Ok(hmac_md5(&nt_hash.0[..16], &identity))
}

/// The LMv2 response: HMAC-MD5 over the two challenges, then the client
/// challenge again.
///
/// `Curl_ntlm_core_mk_lmv2_resp` (`lib/curl_ntlm_core.c:641-663`).
///
/// # The server challenge comes first
///
/// `:650-651`, and the order is the whole content of the function:
///
/// ```c
/// memcpy(&data[0], challenge_server, 8);
/// memcpy(&data[8], challenge_client, 8);
/// ```
///
/// Reversing them yields a well-formed 24-byte response that authenticates
/// nothing. The parameters are named for the C's, but note that the C's own
/// documentation block at `:634-637` labels the third parameter
/// `challenge_client` twice -- a copy-paste slip in the comment, not in the
/// code, and the signature at `:641-644` is the authority. The order here
/// follows the code.
///
/// The result is the 16-byte digest followed by the eight-byte client
/// challenge (`:659-660`), which is what makes the response verifiable: the
/// server learns the client's contribution from the response itself.
pub(crate) fn mk_lmv2_resp(
    ntlmv2_hash: &[u8; 16],
    challenge_client: &[u8; CHALLENGE_LEN],
    challenge_server: &[u8; CHALLENGE_LEN],
) -> [u8; RESPONSE_LEN] {
    let mut data = [0u8; 16];
    data[0..8].copy_from_slice(challenge_server);
    data[8..16].copy_from_slice(challenge_client);

    let digest = hmac_md5(ntlmv2_hash, &data);

    let mut out = [0u8; RESPONSE_LEN];
    out[0..16].copy_from_slice(&digest);
    out[16..24].copy_from_slice(challenge_client);

    out
}

/// A Windows FILETIME: tenths of a microsecond since 1601-01-01, split into
/// two 32-bit halves.
///
/// `struct ms_filetime` (`lib/curl_ntlm_core.c:440-443`), whose comment gives
/// the unit and MS-DTYP section 2.3.3 as the reference. The split is not an
/// implementation detail of the C: the blob writes the two halves as two
/// separate `LONGQUARTET`s (`:601-602`), so the pair is the wire shape.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MsFiletime {
    /// `dwLowDateTime`: bits 0 through 31.
    low: u32,
    /// `dwHighDateTime`: bits 32 through 63.
    high: u32,
}

impl MsFiletime {
    /// The eight bytes the blob carries at offset 24: low half then high
    /// half, each little-endian.
    ///
    /// `lib/curl_ntlm_core.c:597-602` -- one `"%c%c%c%c%c%c%c%c"` fed
    /// `LONGQUARTET(tw.dwLowDateTime)` then `LONGQUARTET(tw.dwHighDateTime)`.
    /// The result is a little-endian 64-bit value, which is what
    /// `:560-561` specifies.
    fn to_le_bytes(self) -> [u8; 8] {
        let low = longquartet(self.low);
        let high = longquartet(self.high);
        [
            low[0], low[1], low[2], low[3], high[0], high[1], high[2], high[3],
        ]
    }
}

/// Converts Unix epoch seconds to an MS FILETIME.
///
/// `time2filetime` (`lib/curl_ntlm_core.c:446-487`), **64-bit arm only**:
///
/// ```c
/// #if SIZEOF_TIME_T > 4
///   t = (t + (curl_off_t)11644473600) * 10000000;
///   ft->dwLowDateTime = (unsigned int)(t & 0xFFFFFFFF);
///   ft->dwHighDateTime = (unsigned int)(t >> 32);
/// #else
/// ```
///
/// The 32-bit `#else` arm (`:452-486`) is 35 lines of split-shift arithmetic
/// that exists solely to avoid a 64-bit multiply on a platform with a 32-bit
/// `time_t`. All four mandated targets are 64-bit, so it is excluded and the
/// exclusion is deliberate rather than an omission.
///
/// # Arithmetic
///
/// C computes in `curl_off_t`, a signed 64-bit type, and the product
/// overflows for any `t` beyond roughly the year 30828 -- undefined behaviour
/// there, in C. Here the bias and the multiply are done with
/// [`u64::saturating_mul`] over a value clamped at zero, so a clock reading
/// far in the future produces the maximum FILETIME rather than a wrapped one,
/// and a reading before 1601 produces zero. Neither is reachable from a real
/// clock; both are reachable from an injected one, and a panic inside an
/// authentication exchange is not an acceptable answer to a wrong clock.
///
/// A negative `t` -- a wall clock set before 1970 -- is meaningful and is
/// handled: the bias is added first, so any instant from 1601 onwards
/// converts correctly.
fn time2filetime(epoch_secs: i64) -> MsFiletime {
    // `t + 11644473600`, in signed arithmetic so that a pre-1970 reading is
    // biased upward rather than wrapping, then clamped at the FILETIME epoch.
    let biased = epoch_secs
        .checked_add_unsigned(FILETIME_EPOCH_BIAS_SECS)
        .unwrap_or(i64::MAX)
        .max(0);

    // The `.max(0)` above proves the value is non-negative, so this is the
    // one conversion in the file that cannot fail; `unwrap_or(0)` names the
    // unreachable arm without introducing a panic.
    let ticks = u64::try_from(biased)
        .unwrap_or(0)
        .saturating_mul(FILETIME_TICKS_PER_SEC);

    let bytes = ticks.to_le_bytes();
    MsFiletime {
        low: read32_le([bytes[0], bytes[1], bytes[2], bytes[3]]),
        high: read32_le([bytes[4], bytes[5], bytes[6], bytes[7]]),
    }
}

/// The NTLMv2 response: a 16-byte HMAC over a blob, followed by the blob.
///
/// `Curl_ntlm_core_mk_ntlmv2_resp` (`lib/curl_ntlm_core.c:548-625`). The
/// layout is in the module documentation; the arithmetic is:
///
/// ```c
/// #define NTLMv2_BLOB_LEN (44 - 16 + ntlm->target_info_len + 4)
/// len = HMAC_MD5_LENGTH + NTLMv2_BLOB_LEN;
/// ```
///
/// `44 - 16 + 4` is 32, so the blob is `32 + target_info_len` bytes and the
/// response is `48 + target_info_len`. The buffer is `calloc`ed (`:589`), so
/// every field the code does not write -- the four reserved bytes at blob
/// offset 4, the four "unknown" bytes at 24, and the four at the end -- is
/// zero. That is reproduced with a zero-filled [`Vec`], not with explicit
/// writes, for the same reason C reproduces it with `calloc`: a field written
/// nowhere cannot be written wrongly.
///
/// # The overlapping-buffer trick is the algorithm
///
/// `:604-618` is the part that looks like a bug and is not:
///
/// ```c
/// memcpy(ptr + 32, challenge_client, 8);
/// if(ntlm->target_info_len) memcpy(ptr + 44, ntlm->target_info, ...);
/// memcpy(ptr + 8, &ntlm->nonce[0], 8);                       /* (1) */
/// Curl_hmacit(&Curl_HMAC_MD5, ntlmv2hash, HMAC_MD5_LENGTH,
///             ptr + 8, NTLMv2_BLOB_LEN + 8, hmac_output);    /* (2) */
/// memcpy(ptr, hmac_output, HMAC_MD5_LENGTH);                 /* (3) */
/// ```
///
/// Step (1) writes the **server** challenge into bytes 8 through 15, which
/// are part of the not-yet-written HMAC field. Step (2) then digests
/// `NTLMv2_BLOB_LEN + 8` bytes starting at offset 8 -- that is, the server
/// challenge **concatenated with the whole blob**. Step (3) overwrites bytes
/// 0 through 15 with the digest, erasing the challenge again.
///
/// So the HMAC input is `server_challenge || blob`, and the eight bytes at
/// offset 8 exist only for the duration of the digest. This implementation
/// assembles the blob once and digests `server_challenge || blob` from an
/// explicit scratch buffer, which produces byte-identical input and
/// byte-identical output while making the sequence readable. A test asserts
/// the final HMAC equals `hmac_md5(v2hash, server_challenge || blob)`
/// independently of this function.
///
/// # The timestamp
///
/// From the injected [`Clock`], through [`time2filetime`]. C reads
/// `time(NULL)` (`:583`) unless `CURL_FORCETIME` is set in a debug build
/// (`:577-582`), in which case it forces zero; a clock whose `epoch_secs()`
/// reads zero reproduces the forced path exactly. See the module
/// documentation.
///
/// # Errors
///
/// None: it cannot fail. C returns `CURLE_OUT_OF_MEMORY` for its `calloc`
/// (`:590-591`) and propagates the HMAC's own code (`:612-615`); neither has
/// a counterpart here, since [`Vec`] allocation aborts rather than returning
/// and [`hmac_md5`] is infallible. The type therefore says so, rather than
/// carrying a result no caller can observe.
pub(crate) fn mk_ntlmv2_resp(
    ntlmv2_hash: &[u8; 16],
    challenge_client: &[u8; CHALLENGE_LEN],
    ntlm: &NtlmData,
    clock: &dyn Clock,
) -> Vec<u8> {
    let target_info = ntlm.target_info();

    // `NTLMv2_BLOB_LEN`, spelled as the C spells it so the two can be
    // compared without re-deriving: 44 - 16 + target_info_len + 4.
    let blob_len = (44 - 16) + target_info.len() + 4;
    debug_assert_eq!(blob_len, 32 + target_info.len());

    // `calloc(1, len)`: everything not written below stays zero, which is
    // where the reserved long at blob offset 4 and the two four-byte
    // "unknown" fields come from.
    let mut blob = vec![0u8; blob_len];

    // Blob offset 0 (response offset 16): the signature.
    blob[0..4].copy_from_slice(&NTLMV2_BLOB_SIGNATURE);

    // Blob offset 4 (response offset 20): reserved, left zero.

    // Blob offset 8 (response offset 24): the timestamp.
    let filetime = time2filetime(clock.epoch_secs());
    blob[8..16].copy_from_slice(&filetime.to_le_bytes());

    // Blob offset 16 (response offset 32): the client nonce.
    blob[16..24].copy_from_slice(challenge_client);

    // Blob offset 24..28 (response offset 40): unknown, left zero.

    // Blob offset 28 (response offset 44): the target info, then four more
    // zero bytes. `if(ntlm->target_info_len)` is implicit: an empty slice
    // copies nothing.
    blob[28..28 + target_info.len()].copy_from_slice(target_info);

    // The HMAC input: the SERVER challenge followed by the whole blob. This
    // is what C's write-into-offset-8 achieves; see the note above.
    let mut hmac_input = Vec::with_capacity(CHALLENGE_LEN + blob_len);
    hmac_input.extend_from_slice(ntlm.nonce());
    hmac_input.extend_from_slice(&blob);
    debug_assert_eq!(hmac_input.len(), blob_len + 8);

    let digest = hmac_md5(ntlmv2_hash, &hmac_input);

    // `len = HMAC_MD5_LENGTH + NTLMv2_BLOB_LEN`: the digest, then the blob.
    let mut response = Vec::with_capacity(16 + blob_len);
    response.extend_from_slice(&digest);
    response.extend_from_slice(&blob);

    response
}

// ---------------------------------------------------------------------------
// The type-1 message. `lib/vauth/ntlm.c:423-526`.
// ---------------------------------------------------------------------------

/// Builds a type-1 message: exactly [`TYPE1_SIZE`] bytes, always the same
/// thirty-two.
///
/// `Curl_auth_create_ntlm_type1_message` (`lib/vauth/ntlm.c:423-526`). The
/// layout is in the module documentation. The emission sequence, in C's
/// order (`:464-494`):
///
/// 1. the signature, all eight bytes including its NUL;
/// 2. `01 00 00 00`, the message type;
/// 3. the flag word, [`TYPE1_FLAGS`], little-endian;
/// 4. the domain security buffer -- length, allocated size, offset, two
///    zeroes;
/// 5. the workstation security buffer, the same five fields;
/// 6. the domain and host strings themselves.
///
/// Steps 4 through 6 contribute nothing but zeroes, because
/// `size = 32 + hostlen + domlen` (`:500`) with both lengths zero.
///
/// # It takes no arguments beyond the state
///
/// The C signature has `userp`, `passwdp`, `service` and `hostname`, and
/// discards all four: `(void)userp; (void)passwdp; (void)service;
/// (void)hostname;` at `:456-459`, with `host` and `domain` hard-coded empty
/// at `:448-449`. A type-1 message carries no identity, so accepting four
/// parameters here in order to ignore them would advertise an influence that
/// does not exist, and a caller would eventually pass something and expect it
/// to matter. [`output_ntlm`] documents the divergence at the one call site.
///
/// # It cleans up first
///
/// `Curl_auth_cleanup_ntlm(ntlm)` at `:462`, commented "Clean up any former
/// leftovers and initialise to defaults". That discards a Target Information
/// block left by an earlier exchange on the same connection and, deliberately,
/// leaves the flag word and challenge alone -- see [`NtlmData::cleanup`].
///
/// Infallible. C's only failure is the `curl_maprintf` allocation
/// (`:496-497`).
pub(crate) fn create_type1_message(ntlm: &mut NtlmData) -> Vec<u8> {
    // `Curl_auth_cleanup_ntlm(ntlm);` -- before anything is composed.
    ntlm.cleanup();

    // `const char *host = ""; const char *domain = "";` with every length and
    // offset zero (`:448-454`). Named rather than inlined so that the
    // security buffers below read as the C's do, and so that the reason the
    // message is 32 bytes is visible rather than arithmetic.
    let hostlen = 0usize;
    let domlen = 0usize;
    let hostoff = 0usize;
    // `size_t domoff = hostoff + hostlen;` with the C's own comment: "This is
    // 0: remember that host and domain are empty".
    let domoff = hostoff + hostlen;

    let mut message = Vec::with_capacity(TYPE1_SIZE);

    message.extend_from_slice(&NTLMSSP_SIGNATURE);
    message.extend_from_slice(&TYPE1_MARKER);
    message.extend_from_slice(&longquartet(TYPE1_FLAGS));

    // The domain buffer precedes the workstation buffer in the message even
    // though the C's format string lists the host string first among the
    // trailing `%s`s. Both are empty, so the order of the strings cannot be
    // observed; the order of the BUFFERS can, and this is it.
    message.extend_from_slice(&security_buffer(domlen, domoff));
    message.extend_from_slice(&security_buffer(hostlen, hostoff));

    // `"%s" "%s"` fed `host` then `domain`, both empty (`:493-494`).

    debug_assert_eq!(
        message.len(),
        TYPE1_SIZE,
        "`size = 32 + hostlen + domlen` with both lengths zero"
    );

    message
}

// ---------------------------------------------------------------------------
// The type-2 message. `lib/vauth/ntlm.c:256-392`.
// ---------------------------------------------------------------------------

/// `"NTLM handshake failure (bad type-2 message)"` --
/// `lib/vauth/ntlm.c:367` and `:377`.
///
/// An `infof()` string, so it reaches the user through `--verbose` and its
/// bytes are frozen. A constant so that a test can assert the exact text
/// without restating it.
pub(crate) const BAD_TYPE2: &str =
    "NTLM handshake failure (bad type-2 message)";

/// `"NTLM handshake failure (bad type-2 message). Target Info Offset Len is
/// set incorrect by the peer"` -- `lib/vauth/ntlm.c:272-273`.
///
/// The C splits it across two source lines as adjacent literals, which the
/// preprocessor joins into one line of output with a single space after the
/// full stop. Reproduced as one string for that reason.
pub(crate) const BAD_TYPE2_TARGET_INFO: &str =
    "NTLM handshake failure (bad type-2 message). \
     Target Info Offset Len is set incorrect by the peer";

/// Extracts the Target Information block from a type-2 message.
///
/// `ntlm_decode_type2_target` (`lib/vauth/ntlm.c:256-288`).
///
/// # Every bound here is a security bound
///
/// The offset and the length are read from a message the **peer** composed.
/// The C validates them with three disjuncts (`:269-271`):
///
/// ```c
/// if((target_info_offset > type2len) ||
///    (target_info_offset + target_info_len) > type2len ||
///    target_info_offset < 48) {
/// ```
///
/// -- the offset must be inside the message, the block must end inside the
/// message, and the offset must not point back into the fixed header. All
/// three are reproduced, in the same order, with the same diagnostic and the
/// same error code. The middle sum is computed with [`usize::checked_add`]
/// here where C computes it in `unsigned int`: C cannot overflow it, because
/// the first disjunct short-circuits on any offset large enough to try, and
/// treating an overflow as a rejection preserves that.
///
/// # `target_info_len` is assigned unconditionally, and that is observable
///
/// `:285` sits outside the `if(type2len >= 48)` block and outside the
/// `if(target_info_len > 0)` block:
///
/// ```c
/// ntlm->target_info_len = target_info_len;
/// return CURLE_OK;
/// ```
///
/// So a message too short to carry the fields, or one declaring a
/// zero-length block, sets the length to the `0` the local declaration gave
/// it (`:260`) -- and a block from an **earlier** exchange on the same
/// connection is thereby discarded rather than kept. The C leaves the old
/// *pointer* allocated in that case and only zeroes the length, which leaks
/// but is not otherwise observable: every consumer reads the length first
/// (`lib/curl_ntlm_core.c:437`, `:605-606`). Dropping the block here produces
/// the same observable state and no leak.
///
/// The **bounds-failure** path is different: it returns early, at `:274`,
/// **before** that assignment, so an earlier block survives a rejected one
/// intact. That asymmetry is reproduced too -- this function touches nothing
/// on that path.
///
/// # Errors
///
/// [`CURLcode::BadContentEncoding`] when any bound fails.
fn decode_type2_target(
    ntlm: &mut NtlmData,
    type2: &[u8],
    tracer: &mut Tracer<'_>,
) -> Result<(), CURLcode> {
    // `unsigned short target_info_len = 0;` and
    // `unsigned int target_info_offset = 0;` (`:260-261`), which stay zero
    // when the message is too short to carry the fields at all.
    if type2.len() < 48 {
        // `if(type2len >= 48)` fails, then `ntlm->target_info_len = 0` runs.
        ntlm.target_info = None;
        return Ok(());
    }

    let target_info_len = usize::from(read16_le([type2[40], type2[41]]));
    let target_info_offset =
        read32_le([type2[44], type2[45], type2[46], type2[47]]);

    if target_info_len == 0 {
        // `if(target_info_len > 0)` fails, then the same zeroing runs.
        ntlm.target_info = None;
        return Ok(());
    }

    // `target_info_offset` is 32 bits wide in C and is compared against a
    // `size_t`. Widening rather than narrowing keeps every comparison below
    // exact. The conversion is total on every mandated target and on any
    // 32-bit one too -- `usize` is at least as wide as `u32` on all of them --
    // so the `else` arm is unreachable; it rejects rather than panicking
    // because this function's whole input is peer-controlled.
    let Ok(offset) = usize::try_from(target_info_offset) else {
        infof!(tracer, "{}", BAD_TYPE2_TARGET_INFO);
        return Err(CURLcode::BadContentEncoding);
    };
    let end = offset.checked_add(target_info_len);

    if offset > type2.len()
        || end.map_or(true, |last| last > type2.len())
        || offset < 48
    {
        infof!(tracer, "{}", BAD_TYPE2_TARGET_INFO);
        return Err(CURLcode::BadContentEncoding);
    }

    // `curlx_free(ntlm->target_info); ntlm->target_info = curlx_memdup(...)`
    // (`:277-279`) -- "replace any previous data". Assigning the field is
    // that free and that duplication in one step.
    //
    // The three disjuncts above prove `offset + target_info_len` is within
    // the message, so this range cannot be out of bounds.
    ntlm.target_info = Some(type2[offset..offset + target_info_len].to_vec());

    Ok(())
}

/// Decodes a type-2 message into `ntlm`.
///
/// `Curl_auth_decode_ntlm_type2_message` (`lib/vauth/ntlm.c:335-392`). The
/// layout is in the module documentation.
///
/// # The flag word is cleared before validation, not after
///
/// `ntlm->flags = 0;` at `:361`, **above** the validation block. That matters
/// on the failure path: a rejected message leaves the state with no flags
/// rather than with whatever the previous exchange negotiated, so a caller
/// that ignores the error and composes a type-3 message anyway produces an
/// NTLMv1 message rather than one keyed on stale terms. Reproduced in the
/// same order.
///
/// # The three validations
///
/// `:363-369`, one `if` with three disjuncts, any of which rejects the
/// message with the same diagnostic and the same code:
///
/// 1. `type2len < 32` -- shorter than the fixed header.
/// 2. `memcmp(type2, NTLMSSP_SIGNATURE, 8) != 0` -- **eight** bytes,
///    including the signature's NUL.
/// 3. `memcmp(type2 + 8, type2_marker, 4) != 0` -- the message type is 2.
///
/// Then the flag word comes from offset 20 and the challenge from offset 24
/// (`:371-372`), and the Target Information block is extracted only when the
/// flag word asks for it (`:374-380`).
///
/// # The input is entirely attacker-controlled
///
/// Everything after the base64 decode is bytes a peer chose. There is no
/// slicing here that is not preceded by a length check, no indexing that
/// depends on a peer-supplied offset outside [`decode_type2_target`]'s
/// validated range, and no path that panics.
///
/// # Errors
///
/// [`CURLcode::BadContentEncoding`] from either validation stage. Note that
/// the C re-emits [`BAD_TYPE2`] when the target-info stage fails (`:377`),
/// **in addition** to the more specific diagnostic that stage already emitted
/// -- two lines for one failure. That is reproduced: it is `--verbose`
/// output and a fixture comparing it would see both.
pub(crate) fn decode_type2_message(
    ntlm: &mut NtlmData,
    type2: &[u8],
    tracer: &mut Tracer<'_>,
) -> Result<(), CURLcode> {
    // `ntlm->flags = 0;` -- before the validation, deliberately.
    ntlm.flags = NtlmFlags::NONE;

    if type2.len() < 32
        || type2[..8] != NTLMSSP_SIGNATURE
        || type2[8..12] != TYPE2_MARKER
    {
        // "This was not a good enough type-2 message"
        infof!(tracer, "{}", BAD_TYPE2);
        return Err(CURLcode::BadContentEncoding);
    }

    ntlm.flags = NtlmFlags::from_bits(read32_le([
        type2[20], type2[21], type2[22], type2[23],
    ]));
    ntlm.nonce.copy_from_slice(&type2[24..32]);

    if ntlm.flags.contains(NTLMFLAG_NEGOTIATE_TARGET_INFO) {
        if let Err(error) = decode_type2_target(ntlm, type2, tracer) {
            // `infof(data, "NTLM handshake failure (bad type-2 message)");`
            // a second time, after the specific diagnostic (`:377`).
            infof!(tracer, "{}", BAD_TYPE2);
            return Err(error);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// The type-3 message. `lib/vauth/ntlm.c:544-838`.
// ---------------------------------------------------------------------------

/// `"incoming NTLM message too big"` -- `lib/vauth/ntlm.c:777`.
///
/// A `failf()` string: it reaches both `--verbose` output and the caller's
/// `CURLOPT_ERRORBUFFER`, so its bytes are frozen. The wording says
/// "incoming" although the message being composed is outgoing; the size that
/// overflows comes from the **incoming** type-2 message's Target Information
/// block, which is presumably what it means. It is transcribed verbatim
/// regardless: a diagnostic that "corrects" the source is one a reader can no
/// longer check against it.
pub(crate) const MESSAGE_TOO_BIG: &str = "incoming NTLM message too big";

/// `"user + domain + hostname too big for NTLM"` --
/// `lib/vauth/ntlm.c:800`. A `failf()` string, so frozen output.
pub(crate) const IDENTITY_TOO_BIG: &str =
    "user + domain + hostname too big for NTLM";

/// Splits `"DOMAIN\\user"` or `"DOMAIN/user"` into its two parts.
///
/// `lib/vauth/ntlm.c:593-603`:
///
/// ```c
/// user = strchr(userp, '\\');
/// if(!user)
///   user = strchr(userp, '/');
/// if(user) {
///   domain = userp;
///   domlen = (user - domain);
///   user++;
/// }
/// else
///   user = userp;
/// ```
///
/// Backslash **first**, forward slash only if there is no backslash. The
/// order is observable: in `"a/b\\c"` the separator is the backslash, so the
/// domain is `"a/b"` and the user is `"c"`, where a slash-first
/// implementation would say `"a"` and `"b\\c"`.
///
/// `strchr` finds the **first** occurrence, so `"a\\b\\c"` splits at the
/// first backslash: domain `"a"`, user `"b\\c"`. Both are asserted by test.
///
/// With no separator the domain is `""` (`:583`), never the user string.
///
/// Returns `(domain, user)` in the order the message writes them.
fn split_user(userp: &[u8]) -> (&[u8], &[u8]) {
    let separator = userp
        .iter()
        .position(|&byte| byte == b'\\')
        .or_else(|| userp.iter().position(|&byte| byte == b'/'));

    match separator {
        // `user++` steps over the separator itself, which is why the user
        // slice starts one past it and the separator appears in neither part.
        Some(at) => (&userp[..at], &userp[at + 1..]),
        None => (&[], userp),
    }
}

/// Builds a type-3 message answering the type-2 message already decoded into
/// `ntlm`.
///
/// `Curl_auth_create_ntlm_type3_message` (`lib/vauth/ntlm.c:544-838`). The
/// layout is in the module documentation.
///
/// # Which version is used, and by whose choice
///
/// `if(ntlm->flags & NTLMFLAG_NEGOTIATE_NTLM2_KEY)` at `:608`: the **server**
/// decides, by echoing or clearing bit 19 in its type-2 message. curl's
/// comment on the version-2 branch (`:613-616`) explains why it is taken
/// whenever offered: *"Full NTLM version 2. Although this cannot be
/// negotiated, it is used here if available, as servers featuring extended
/// security are likely supporting also NTLMv2."*
///
/// The version-1 branch **clears the bit from the emitted flag word**
/// (`:662`), so the type-3 message tells the server which scheme its
/// responses were computed under. A test asserts the clear.
///
/// curl records a *"safer but less compatible alternative"* in a comment at
/// `:664-666` -- keying the LM slot with the NT hash instead of the LM hash.
/// It is **not** adopted, because it is deliberately not what curl does and
/// adopting it would change 24 bytes of every NTLMv1 message.
///
/// # Offsets, in the order that makes them right
///
/// `:669-679`. The Unicode doubling happens **first**, and every offset is
/// derived from the doubled lengths:
///
/// ```c
/// if(unicode) { domlen *= 2; userlen *= 2; hostlen *= 2; }
/// lmrespoff = 64;
/// ntrespoff = lmrespoff + 0x18;
/// domoff    = ntrespoff + ntresplen;
/// useroff   = domoff + domlen;
/// hostoff   = useroff + userlen;
/// ```
///
/// `lmrespoff` is **always 64** and `ntrespoff` **always 88**, because the LM
/// slot is always 24 bytes wide -- in the version-2 path too, where it holds
/// an LMv2 response that also happens to be 24 bytes. The LM security
/// buffer's two length fields are correspondingly the literal `0x18` in both
/// paths, written as a literal rather than computed from a variable, exactly
/// as `:728-730` does.
///
/// # The two size guards
///
/// Both compare against [`NTLM_BUFSIZE`] and both fail the transfer with
/// [`CURLcode::TooLarge`]:
///
/// * `if(ntresplen + size > sizeof(ntlmbuf))` (`:776-780`), reached with
///   `size` at 88, so an NTLMv2 response longer than 936 bytes -- a Target
///   Information block above 888 -- is rejected with [`MESSAGE_TOO_BIG`].
/// * `if(size + userlen + domlen + hostlen >= NTLM_BUFSIZE)` (`:799-803`),
///   rejected with [`IDENTITY_TOO_BIG`]. Note `>=`, not `>`.
///
/// # Cleanup runs on both paths
///
/// `:832-835` is reached by the `goto error` of both guards **and** by
/// falling off the success path, and it calls `Curl_auth_cleanup_ntlm(ntlm)`
/// either way. So a Target Information block is never carried into a second
/// type-3 message. Reproduced by a single cleanup before every return.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from either guard, and
/// [`CURLcode::OutOfMemory`] from [`mk_nt_hash`] or [`mk_ntlmv2_hash`].
pub(crate) fn create_type3_message(
    ntlm: &mut NtlmData,
    userp: &[u8],
    passwdp: &[u8],
    rng: &mut dyn Rng,
    clock: &dyn Clock,
    tracer: &mut Tracer<'_>,
) -> Result<Vec<u8>, CURLcode> {
    let result = build_type3(ntlm, userp, passwdp, rng, clock, tracer);

    // `error:` at `:832` -- reached by both `goto`s and by the success path.
    // `curlx_free(ntlmv2resp)` has no counterpart: the NTLMv2 response is an
    // owned `Vec` inside `build_type3` and is dropped when it goes out of
    // scope, on every path, which is what that `free` was for.
    ntlm.cleanup();

    result
}

/// The body of [`create_type3_message`], so that its cleanup can be
/// unconditional.
///
/// Separated for exactly one reason: the C's `goto error` runs the cleanup on
/// the failure paths as well as the success path, and the honest Rust
/// expression of "this runs whatever happens" is a caller that always runs
/// it. Every citation and every guard is in [`create_type3_message`]'s
/// documentation; this function is that documentation's code.
fn build_type3(
    ntlm: &mut NtlmData,
    userp: &[u8],
    passwdp: &[u8],
    rng: &mut dyn Rng,
    clock: &dyn Clock,
    tracer: &mut Tracer<'_>,
) -> Result<Vec<u8>, CURLcode> {
    // `bool unicode = (ntlm->flags & NTLMFLAG_NEGOTIATE_UNICODE);` (`:578`).
    let unicode = ntlm.flags.contains(NTLMFLAG_NEGOTIATE_UNICODE);

    // `user = strchr(userp, '\\'); ...` (`:593-603`).
    let (domain, user) = split_user(userp);

    // `userlen = strlen(user); hostlen = sizeof(host) - 1;` (`:605-606`).
    // Byte lengths before the Unicode doubling below.
    let mut domlen = domain.len();
    let mut userlen = user.len();
    let mut hostlen = TYPE3_WORKSTATION.len();
    debug_assert_eq!(hostlen, 11, "sizeof(\"WORKSTATION\") - 1");

    // `unsigned char lmresp[24]` and `ntresp[24]`, both `memset` to zero at
    // `:591-592`. `ntresplen` starts at 24 (`:574`) and the version-2 branch
    // replaces both the length and the response.
    //
    // The C's two `memset`s are defensive and unobservable: both branches
    // below write all 24 bytes of the LM slot, and the `ntresp` array is not
    // read at all on the version-2 path, where `ptr_ntresp` is repointed at
    // the heap response instead. Declaring without an initialiser says the
    // same thing and lets the compiler prove it, where a zero-fill that is
    // always overwritten would only look like it mattered.
    let lmresp: [u8; RESPONSE_LEN];
    let ntresp_v1;
    let ntresp_v2;
    let ntresp: &[u8];

    if ntlm.flags.contains(NTLMFLAG_NEGOTIATE_NTLM2_KEY) {
        // Full NTLM version 2. `:608-643`.
        //
        // `Curl_rand(data, entropy, 8)` (`:617`): the client challenge, from
        // the injected generator rather than a global. C returns its error;
        // `Rng::fill_bytes` is infallible because acquiring entropy failed
        // once, at construction.
        let mut entropy = [0u8; CHALLENGE_LEN];
        rng.fill_bytes(&mut entropy);

        let nt_hash = mk_nt_hash(passwdp)?;
        let v2_hash = mk_ntlmv2_hash(user, domain, &nt_hash)?;

        // LMv2 response (`:631-632`). Note the argument order: the client
        // challenge is second and the server challenge third, and
        // `mk_lmv2_resp` writes the SERVER one first.
        lmresp = mk_lmv2_resp(&v2_hash, &entropy, ntlm.nonce());

        // NTLMv2 response (`:637-638`), which also determines `ntresplen`.
        ntresp_v2 = mk_ntlmv2_resp(&v2_hash, &entropy, ntlm, clock);
        ntresp = &ntresp_v2;
    } else {
        // NTLM version 1. `:644-667`.
        let nt_hash = mk_nt_hash(passwdp)?;
        ntresp_v1 = lm_resp(&nt_hash, ntlm.nonce());

        let lm_hash = mk_lm_hash(passwdp);
        lmresp = lm_resp(&lm_hash, ntlm.nonce());

        // `ntlm->flags &= ~(unsigned int)NTLMFLAG_NEGOTIATE_NTLM2_KEY;`
        // (`:662`) -- the emitted flag word says which scheme was used.
        ntlm.flags = ntlm.flags.without(NTLMFLAG_NEGOTIATE_NTLM2_KEY);

        ntresp = &ntresp_v1;
    }

    let ntresplen = ntresp.len();

    // `if(unicode) { domlen *= 2; userlen *= 2; hostlen *= 2; }` (`:669-673`)
    // -- BEFORE the offsets, which are all derived from these lengths.
    if unicode {
        domlen *= 2;
        userlen *= 2;
        hostlen *= 2;
    }

    // `:675-679`.
    let lmrespoff = TYPE3_HEADER_SIZE;
    let ntrespoff = lmrespoff + RESPONSE_LEN;
    let domoff = ntrespoff + ntresplen;
    let useroff = domoff + domlen;
    let hostoff = useroff + userlen;
    debug_assert_eq!(lmrespoff, 64);
    debug_assert_eq!(ntrespoff, 88);

    // The header. `:682-759`, one `curl_msnprintf` of exactly 64 bytes.
    let mut message = Vec::with_capacity(NTLM_BUFSIZE);

    message.extend_from_slice(&NTLMSSP_SIGNATURE);
    message.extend_from_slice(&TYPE3_MARKER);

    // The LM security buffer. `SHORTPAIR(0x18)` TWICE, as a LITERAL: the slot
    // is 24 bytes wide in both the version-1 and the version-2 path, so this
    // is not `ntresplen` and not `lmresp.len()` but the number the C writes.
    message.extend_from_slice(&security_buffer(0x18, lmrespoff));

    // The NT security buffer -- the one length that does vary.
    message.extend_from_slice(&security_buffer(ntresplen, ntrespoff));

    // Target name, username, workstation.
    message.extend_from_slice(&security_buffer(domlen, domoff));
    message.extend_from_slice(&security_buffer(userlen, useroff));
    message.extend_from_slice(&security_buffer(hostlen, hostoff));

    // The session-key security buffer: eight ZERO bytes. The C writes four
    // literal pairs (`:754-757`) under the comment "session key length
    // (unknown purpose)". curl never sends a session key, so this is not a
    // buffer whose length happens to be zero -- it is a field that is always
    // zero, which is why it is written as zeroes rather than through
    // `security_buffer`.
    message.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

    // The flag word. `LONGQUARTET(ntlm->flags)` (`:759`), read AFTER the
    // version-1 branch cleared bit 19 from it.
    message.extend_from_slice(&longquartet(ntlm.flags.bits()));

    // `DEBUGASSERT(size == 64); DEBUGASSERT(size == (size_t)lmrespoff);`
    // (`:761-762`).
    debug_assert_eq!(message.len(), TYPE3_HEADER_SIZE);
    debug_assert_eq!(message.len(), lmrespoff);

    // "We append the binary hashes" (`:764-768`). The guard is C's and is
    // always true here -- 64 is below 1000 -- but it is reproduced rather
    // than dropped: were it false the C would omit the LM response and carry
    // on with a message whose offsets no longer describe it, and an
    // implementation that instead appended unconditionally would diverge on
    // that path.
    if message.len() < NTLM_BUFSIZE - RESPONSE_LEN {
        message.extend_from_slice(&lmresp);
    }

    // `if(ntresplen + size > sizeof(ntlmbuf))` (`:776-780`). C's own comment
    // is "ntresplen + size should not be risking an integer overflow here";
    // `checked_add` removes the "should".
    let with_ntresp = ntresplen.checked_add(message.len());
    if with_ntresp.map_or(true, |total| total > NTLM_BUFSIZE) {
        failf!(tracer, "{}", MESSAGE_TOO_BIG);
        return Err(CURLcode::TooLarge);
    }

    // `DEBUGASSERT(size == (size_t)ntrespoff);` (`:781`).
    debug_assert_eq!(message.len(), ntrespoff);
    message.extend_from_slice(ntresp);

    // "Make sure that the domain, user and host strings fit in the buffer
    // before we copy them there." (`:797-803`). Note `>=`.
    let with_strings = message
        .len()
        .checked_add(userlen)
        .and_then(|sum| sum.checked_add(domlen))
        .and_then(|sum| sum.checked_add(hostlen));
    if with_strings.map_or(true, |total| total >= NTLM_BUFSIZE) {
        failf!(tracer, "{}", IDENTITY_TOO_BIG);
        return Err(CURLcode::TooLarge);
    }

    // The three strings, each widened or copied as the flag word dictates
    // (`:805-827`). The C's `unicodecpy(&ntlmbuf[size], domain, domlen / 2)`
    // halves the already-doubled length to recover the source length; here
    // the source slice is passed directly and the widening produces the
    // doubled length, which the assertions confirm.
    debug_assert_eq!(message.len(), domoff);
    message.extend_from_slice(&widen_or_copy(domain, unicode));

    debug_assert_eq!(message.len(), useroff);
    message.extend_from_slice(&widen_or_copy(user, unicode));

    debug_assert_eq!(message.len(), hostoff);
    message.extend_from_slice(&widen_or_copy(TYPE3_WORKSTATION, unicode));

    Ok(message)
}

/// One of the two string-copy arms of the type-3 message.
///
/// `lib/vauth/ntlm.c:806-825` writes the same two-line choice three times:
///
/// ```c
/// if(unicode)
///   unicodecpy(&ntlmbuf[size], domain, domlen / 2);
/// else
///   memcpy(&ntlmbuf[size], domain, domlen);
/// ```
///
/// Written once here. See [`unicodecpy`] on why the widening is naive and
/// must stay that way.
fn widen_or_copy(src: &[u8], unicode: bool) -> Vec<u8> {
    if unicode {
        unicodecpy(src)
    } else {
        copy_bytes(src)
    }
}

// ---------------------------------------------------------------------------
// The HTTP exchange. `lib/http_ntlm.c:51-252`.
// ---------------------------------------------------------------------------

/// `"NTLM auth restarted"` -- `lib/http_ntlm.c:90`. An `infof()` string, so
/// frozen `--verbose` output.
pub(crate) const AUTH_RESTARTED: &str = "NTLM auth restarted";

/// `"NTLM handshake rejected"` -- `lib/http_ntlm.c:94`.
pub(crate) const HANDSHAKE_REJECTED: &str = "NTLM handshake rejected";

/// `"NTLM handshake failure (internal error)"` -- `lib/http_ntlm.c:100`.
pub(crate) const HANDSHAKE_INTERNAL_ERROR: &str =
    "NTLM handshake failure (internal error)";

/// Consumes a `WWW-Authenticate:` or `Proxy-Authenticate:` NTLM challenge.
///
/// `Curl_input_ntlm` (`lib/http_ntlm.c:51-109`). `header` starts at the
/// scheme token, exactly as C's `header` pointer does, and extends to the end
/// of the header value.
///
/// Two shapes arrive and they mean different things:
///
/// * **`NTLM <base64>`** -- a type-2 message. It is decoded into the
///   connection's [`NtlmData`] and the state becomes
///   [`NtlmState::Type2`] (`:70-87`).
/// * **bare `NTLM`** -- the server is advertising the mechanism, or answering
///   one. Three states are distinguished (`:89-102`), each with its own
///   verbatim diagnostic, and then the state becomes [`NtlmState::Type1`]
///   (`:104`).
///
/// A header that is not NTLM at all is silently ignored: the C's whole body
/// is inside `if(checkprefix("NTLM", header))` and it returns `CURLE_OK`
/// otherwise.
///
/// # The three bare-`NTLM` states
///
/// | State | Diagnostic | Effect |
/// |-------|------------|--------|
/// | [`NtlmState::Last`] | [`AUTH_RESTARTED`] | data removed, then `Type1` |
/// | [`NtlmState::Type3`] | [`HANDSHAKE_REJECTED`] | data removed, state `None`, error |
/// | `>= `[`NtlmState::Type1`] | [`HANDSHAKE_INTERNAL_ERROR`] | error, state left alone |
///
/// The third arm is `else if(*state >= NTLMSTATE_TYPE1)`, which after the
/// first two have been excluded means exactly [`NtlmState::Type1`] and
/// [`NtlmState::Type2`]: the server sent a bare `NTLM` in the middle of a
/// handshake. The ordering of the enumeration is what makes the comparison
/// mean that, which is why [`NtlmState`] derives [`PartialOrd`].
///
/// Note that the second arm sets the state to [`NtlmState::None`] before
/// returning while the third leaves it untouched -- a difference the C is
/// explicit about and which a shared "reset on error" would lose.
///
/// # Errors
///
/// [`CURLcode::RemoteAccessDenied`] from the second and third arms.
/// [`CURLcode::BadContentEncoding`] from a base64 payload that will not
/// decode, or from [`decode_type2_message`].
///
/// The C's `CURLE_OUT_OF_MEMORY` for a `NULL` from `Curl_auth_ntlm_get`
/// (`:65-66`) has no counterpart: [`NtlmConnection::data_mut`] cannot fail.
pub(crate) fn input_ntlm(
    conn: &mut NtlmConnection,
    proxy: bool,
    header: &[u8],
    tracer: &mut Tracer<'_>,
) -> Result<(), CURLcode> {
    if !checkprefix(NTLM_SCHEME, header) {
        return Ok(());
    }

    // `header += strlen("NTLM"); curlx_str_passblanks(&header);` (`:68-69`).
    // `checkprefix` has already proved the four bytes are there.
    let payload = pass_blanks(&header[NTLM_SCHEME.len()..]);

    if payload.is_empty() {
        // `else` at `:88`: a bare `NTLM` header.
        let state = conn.state(proxy);

        if state == NtlmState::Last {
            infof!(tracer, "{}", AUTH_RESTARTED);
            conn.remove(proxy);
        } else if state == NtlmState::Type3 {
            infof!(tracer, "{}", HANDSHAKE_REJECTED);
            conn.remove(proxy);
            *conn.state_mut(proxy) = NtlmState::None;
            return Err(CURLcode::RemoteAccessDenied);
        } else if state >= NtlmState::Type1 {
            infof!(tracer, "{}", HANDSHAKE_INTERNAL_ERROR);
            return Err(CURLcode::RemoteAccessDenied);
        }

        // "We should send away a type-1" (`:104`). Reached from the `Last`
        // arm and from `None`, which is the only remaining state.
        *conn.state_mut(proxy) = NtlmState::Type1;

        return Ok(());
    }

    // `curlx_base64_decode(header, &hdr, &hdrlen)` then
    // `Curl_auth_decode_ntlm_type2_message(...)` (`:74-84`).
    let decoded = base64::decode(payload)?;
    decode_type2_message(conn.data_mut(proxy), &decoded, tracer)?;

    // "We got a type-2 message" (`:86`).
    *conn.state_mut(proxy) = NtlmState::Type2;

    Ok(())
}

/// Produces this request's NTLM authorization header, or none.
///
/// `Curl_output_ntlm` (`lib/http_ntlm.c:114-252`).
///
/// # The state advances before the switch, not inside it
///
/// `:192-193`, with the C's comment: *"connection is already authenticated,
/// do not send a header in future requests so go directly to
/// NTLMSTATE_LAST"*.
///
/// ```c
/// if(*state == NTLMSTATE_TYPE3)
///   *state = NTLMSTATE_LAST;
/// ```
///
/// So there is no `case NTLMSTATE_TYPE3` in the switch -- by the time it runs,
/// that state has become [`NtlmState::Last`]. Placing the transition inside
/// the match instead would need a fall-through Rust does not have.
///
/// # The arms
///
/// * **[`NtlmState::Type1`] and everything else.** The C writes
///   `case NTLMSTATE_TYPE1: default:` (`:196-197`) with the comment *"for the
///   weird cases we (re)start here"*, so [`NtlmState::None`] -- and any state
///   not otherwise handled -- composes a type-1 message. The catch-all arm
///   below shares that body deliberately. `authp->done` is left **false**,
///   which is [`AuthEmission::Continuing`].
/// * **[`NtlmState::Type2`]**: compose the type-3 message, advance to
///   [`NtlmState::Type3`] and set `done` (`:216-236`), which is
///   [`AuthEmission::Final`].
/// * **[`NtlmState::Last`]**: emit **nothing**, but record the mechanism.
///   The C's comment (`:239-240`) is *"since this is a little artificial in
///   that this is used without any outgoing auth headers being set, we need to
///   set the bit by force"*: it writes `data->info.*authpicked`, frees the
///   credential string so that no header is produced, and sets `done`. That
///   is [`AuthEmission::Nothing`], whose [`AuthEmission::is_done`] is true,
///   plus the write to `picked`.
///
/// # The identity parameters the C threads through and discards
///
/// C reads `service` and `hostname` (`:145-147`, `:158-160`, defaulting the
/// service to [`DEFAULT_SERVICE`]) and passes both to
/// `Curl_auth_create_ntlm_type1_message`, which discards them along with the
/// username and password. [`create_type1_message`] therefore takes none of
/// the four, and this function does not manufacture them: a parameter that
/// cannot affect a byte of output is a parameter a caller will eventually
/// believe in. The divergence is confined to this call site and is recorded
/// here.
///
/// # The proxy branch of a build without proxy support
///
/// `:150-152` returns `CURLE_NOT_BUILT_IN` under `CURL_DISABLE_PROXY`. This
/// crate has no `proxy` feature -- proxy support is unconditional -- so that
/// return is unreachable rather than dropped, and [`CURLcode::NotBuiltIn`] is
/// never produced here. It is documented rather than deleted so that a reader
/// diffing against `lib/http_ntlm.c` finds it accounted for.
///
/// # Errors
///
/// Whatever [`create_type3_message`] returns: [`CURLcode::TooLarge`] from
/// either size guard, [`CURLcode::OutOfMemory`] from the hash helpers.
/// C's base64-encoder and `curl_maprintf` failures are both
/// `CURLE_OUT_OF_MEMORY` (`:210-211`, `:228-229`) and neither can arise here.
pub(crate) fn output_ntlm(
    conn: &mut NtlmConnection,
    credentials: &Credentials,
    picked: &mut AuthPickedInfo,
    ctx: &mut AuthContext<'_>,
    tracer: &mut Tracer<'_>,
) -> Result<AuthEmission, CURLcode> {
    let proxy = ctx.proxy;

    // `if(!userp) userp = ""; if(!passwdp) passwdp = "";` (`:170-174`).
    let userp = credentials.user().unwrap_or(&[]);
    let passwdp = credentials.secret().unwrap_or(&[]);

    // `authp->done = FALSE;` (`:167`) needs no statement: readiness is the
    // return value, and every arm below produces one.

    // `if(*state == NTLMSTATE_TYPE3) *state = NTLMSTATE_LAST;` (`:192-193`).
    if conn.state(proxy) == NtlmState::Type3 {
        *conn.state_mut(proxy) = NtlmState::Last;
    }

    let scheme = AuthScheme::Ntlm.header_scheme().unwrap_or(NTLM_SCHEME);

    match conn.state(proxy) {
        NtlmState::Type2 => {
            // "We already received the type-2 message, create a type-3
            // message" (`:217`).
            let message = create_type3_message(
                conn.data_mut(proxy),
                userp,
                passwdp,
                ctx.rng,
                ctx.clock,
                tracer,
            )?;

            // `if(!result && Curl_bufref_len(&ntlmmsg))` (`:220`): the C
            // skips the header when the message is empty, which only the
            // SSPI arm can produce -- this one always returns at least the
            // 64-byte header, and `build_type3` asserts it.
            debug_assert!(
                !message.is_empty(),
                "a type-3 message is never shorter than its 64-byte header"
            );

            let encoded = base64::encode(&message)?;
            let header = authorization_header(proxy, scheme, &encoded);

            // "we send a type-3" and `authp->done = TRUE;` (`:231-232`).
            *conn.state_mut(proxy) = NtlmState::Type3;

            Ok(AuthEmission::Final(header))
        }

        NtlmState::Last => {
            // "we need to set the bit by force" (`:239-244`).
            picked.set(proxy, AuthMask::NTLM);

            // `Curl_safefree(*allocuserpwd)` (`:245`): the credential string
            // is discarded so that NOTHING is emitted this round.
            Ok(AuthEmission::Nothing)
        }

        // `case NTLMSTATE_TYPE1: default:` -- one body for both. The
        // catch-all is C's `default`, whose comment is "for the weird cases
        // we (re)start here", and it is reached by `NTLMSTATE_NONE`.
        NtlmState::None | NtlmState::Type1 | NtlmState::Type3 => {
            let message = create_type1_message(conn.data_mut(proxy));

            // `DEBUGASSERT(Curl_bufref_len(&ntlmmsg) != 0);` (`:202`).
            debug_assert_eq!(message.len(), TYPE1_SIZE);

            let encoded = base64::encode(&message)?;
            let header = authorization_header(proxy, scheme, &encoded);

            // `authp->done` is NOT set here: a type-1 message is the first of
            // three, so the exchange continues.
            Ok(AuthEmission::Continuing(header))
        }
    }
}

/// One connection's NTLM mechanism, as [`HttpAuthMechanism`].
///
/// The adapter that lets the dispatch layer of [`super`] drive this module
/// without knowing anything about NTLM. It borrows rather than owns
/// everything it touches, because every piece belongs to a different lifetime
/// in C: the state is on the connection, the credentials and `data->info` are
/// on the easy handle, and the tracer is the handle's diagnostic sink.
///
/// # Why the tracer is a field
///
/// [`HttpAuthMechanism::input`] and [`HttpAuthMechanism::output`] take no
/// tracer, and NTLM has five verbatim diagnostics that must reach
/// `--verbose`. Holding it is what lets the trait be implemented without
/// losing them. [`input_ntlm`] and [`output_ntlm`] remain callable directly,
/// with the tracer as an ordinary argument, and are what the tests drive:
/// the trait adds dispatch, not behaviour.
///
/// # It does not implement [`super::ChallengeDecoder`]
///
/// That trait is the *whole scan* -- one implementation dispatches all five
/// schemes from `super::input_auth`, mirroring the `authcmp` chain of
/// `Curl_http_input_auth` -- so it belongs to the HTTP driver, not to one
/// mechanism. [`input_ntlm`] is what such an implementation calls for
/// [`AuthScheme::Ntlm`].
pub(crate) struct NtlmMechanism<'a, 'sink> {
    /// The connection's two exchange states and two data blocks.
    conn: &'a mut NtlmConnection,
    /// `data->state.aptr.user` and `.passwd`, or their proxy counterparts.
    credentials: &'a Credentials,
    /// `data->info.httpauthpicked` and `.proxyauthpicked`.
    picked: &'a mut AuthPickedInfo,
    /// The diagnostic sink the five frozen strings reach.
    tracer: &'a mut Tracer<'sink>,
}

impl<'a, 'sink> NtlmMechanism<'a, 'sink> {
    /// Borrows the four things an NTLM exchange needs.
    #[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
    pub(crate) fn new(
        conn: &'a mut NtlmConnection,
        credentials: &'a Credentials,
        picked: &'a mut AuthPickedInfo,
        tracer: &'a mut Tracer<'sink>,
    ) -> Self {
        Self {
            conn,
            credentials,
            picked,
            tracer,
        }
    }
}

impl fmt::Debug for NtlmMechanism<'_, '_> {
    /// Hand-written because [`Tracer`] and [`Credentials`] have formatters of
    /// their own that decide what is printable, and because a derived one
    /// would require [`fmt::Debug`] on the mutable borrows.
    ///
    /// [`Credentials`] prints its username and a placeholder for its secret,
    /// which is what curl itself prints, so delegating to it is safe.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtlmMechanism")
            .field("conn", &self.conn)
            .field("credentials", &self.credentials)
            .field("picked", &self.picked)
            .finish_non_exhaustive()
    }
}

impl HttpAuthMechanism for NtlmMechanism<'_, '_> {
    fn scheme(&self) -> AuthScheme {
        AuthScheme::Ntlm
    }

    fn input(&mut self, challenge: &[u8], proxy: bool) -> Result<(), CURLcode> {
        input_ntlm(self.conn, proxy, challenge, self.tracer)
    }

    fn output(
        &mut self,
        ctx: &mut AuthContext<'_>,
    ) -> Result<AuthEmission, CURLcode> {
        output_ntlm(self.conn, self.credentials, self.picked, ctx, self.tracer)
    }
}

// Tests
//
// `tests/libtest/*.c` and `tests/unit/*.c` cannot link against this crate:
// they call internal `Curl_*` symbols, and a Rust static library does not
// export `pub(crate)` items -- they are genuinely absent from the symbol table
// rather than merely hidden. Their coverage is relocated here, inside the
// module under test, which is also where a private item is reachable without
// widening its visibility to accommodate a test.
//
// The oracles, in descending order of authority:
//
//   * `tests/data/test1008` and `tests/data/test1021` -- the repository's own
//     fixtures. Their expected type-1 and type-3 messages are decoded from the
//     base64 in those files and written here as LITERAL bytes. This is the
//     strongest oracle available, because it is what the harness will compare.
//   * MS-NLMP section 4.2, the published test vectors of the protocol
//     specification. They pin the primitives independently of curl.
//   * `lib/vauth/ntlm.c`, `lib/curl_ntlm_core.c` and `lib/http_ntlm.c` -- for
//     structure, ordering and diagnostics.
//
// Every expectation that crosses the wire is a literal rather than a value
// derived from the implementation. Deriving it would make the test agree with
// whatever the code does, which is the one thing a parity test must not do.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{TraceConfig, TraceState, WriterSink};
    use crate::util::timeval::TestClock;

    // The dispatch surface this module plugs into. Reached through
    // `crate::auth` rather than `super` because inside this test module
    // `super` is `crate::auth::ntlm`, and these live one level further out.
    use crate::auth::{
        authcmp, header_prefix, is_ntlm_supported, state_scope, StateScope,
        CHALLENGE_ORDER, EMISSION_ORDER, NTLM_FORCE_HTTP11, NTLM_PROBLEM,
        PREFERENCE_ORDER,
    };

    // -----------------------------------------------------------------------
    // Fixtures, decoded from the repository.
    // -----------------------------------------------------------------------

    /// The 32 bytes `tests/data/test1008:108` and `tests/data/test1021:118`
    /// both expect, written exactly as the fixtures spell them.
    ///
    /// The fixtures use `%b64[...]b64%` with `%XX` byte escapes:
    ///
    /// ```text
    /// NTLMSSP%00%01%00%00%00%06%82%08%00%00%00%00%00 ... %00
    /// ```
    ///
    /// -- `NTLMSSP` and its NUL, then `01 00 00 00`, then `06 82 08 00`, then
    /// twenty zero bytes.
    #[rustfmt::skip]
    const FIXTURE_TYPE1: [u8; 32] = [
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x06, 0x82, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// The type-2 message `tests/data/test1008`'s mock proxy sends, decoded
    /// from the `Proxy-Authenticate:` header of its `<connect1001>` reply.
    ///
    /// 160 bytes. Its flag word at offset 20 is `86 82 01 00`, that is
    /// `0x0001_8286` -- bits 1, 2, 7, 9, 15 and 16. So: bit 19 CLEAR, hence
    /// NTLMv1; bit 0 clear, hence not Unicode; and **bit 23 clear**.
    ///
    /// That last one is worth stating, because the message does carry a
    /// Target Information security buffer at offset 40, declaring 110 bytes at
    /// offset 50 -- and curl reads NONE of it, because
    /// `if(ntlm->flags & NTLMFLAG_NEGOTIATE_TARGET_INFO)`
    /// (`lib/vauth/ntlm.c:374`) gates the whole extraction on a flag the
    /// server did not set. An implementation that extracted the block anyway
    /// would still produce the right type-3 message here (NTLMv1 does not use
    /// the block) but would diverge the moment bit 19 were set as well.
    const FIXTURE_TYPE2_B64: &str = "TlRMTVNTUAACAAAAAgACADAAAACGggEAc51AYVDgy\
        NcAAAAAAAAAAG4AbgAyAAAAQ0MCAAQAQwBDAAEAEgBFAEwASQBTAEEAQgBFAFQASAAEABgA\
        YwBjAC4AaQBjAGUAZABlAHYALgBuAHUAAwAsAGUAbABpAHMAYQBiAGUAdABoAC4AYwBjAC4\
        AaQBjAGUAZABlAHYALgBuAHUAAAAAAA==";

    /// The type-3 message `tests/data/test1008:113` expects, decoded from its
    /// base64.
    ///
    /// 131 bytes: the 64-byte header, a 24-byte LM response, a 24-byte NT
    /// response, then `testuser` and `WORKSTATION`. Credentials are
    /// `testuser:testpass`, from the fixture's
    /// `--proxy-user testuser:testpass`.
    const FIXTURE_TYPE3_B64: &str = "TlRMTVNTUAADAAAAGAAYAEAAAAAYABgAWAAAAAAAA\
        ABwAAAACAAIAHAAAAALAAsAeAAAAAAAAAAAAAAAhoIBAFpkQwKRCZFMhjj0tw47wEjKHRHl\
        vzfxQamFcheMuv8v+xeqphEO5V41xRd7R9deOXRlc3R1c2VyV09SS1NUQVRJT04=";

    /// The credentials `tests/data/test1008` and `test1021` both pass through
    /// `--proxy-user`.
    const FIXTURE_USER: &[u8] = b"testuser";
    /// See [`FIXTURE_USER`].
    const FIXTURE_PASSWORD: &[u8] = b"testpass";

    /// The server challenge inside [`FIXTURE_TYPE2_B64`], bytes 24 to 31.
    #[rustfmt::skip]
    const FIXTURE_CHALLENGE: [u8; 8] = [
        0x73, 0x9d, 0x40, 0x61, 0x50, 0xe0, 0xc8, 0xd7,
    ];

    /// The flag word inside [`FIXTURE_TYPE2_B64`], at offset 20.
    const FIXTURE_TYPE2_FLAGS: u32 = 0x0001_8286;

    // -----------------------------------------------------------------------
    // Harness helpers.
    // -----------------------------------------------------------------------

    /// Runs `body` with a verbose tracer and returns its result together with
    /// everything the sink received, as text.
    ///
    /// `WriterSink::new` rather than `new_for_terminal`: the byte-faithful
    /// form is what an assertion on exact text needs, since the terminal form
    /// escapes control bytes.
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

    /// Runs `body` with a tracer whose output is discarded.
    ///
    /// For the majority of assertions, which are about bytes rather than about
    /// diagnostics.
    fn quietly<R>(body: impl FnOnce(&mut Tracer<'_>) -> R) -> R {
        with_tracer(body).0
    }

    /// A generator that hands out a fixed byte, so that a client challenge is
    /// reproducible.
    ///
    /// `TestRng` reproduces `lib/rand.c`'s `CURL_ENTROPY` seam, which is the
    /// right tool for asserting curl's own generated values; here the client
    /// challenge is an opaque input to an HMAC and a constant makes the
    /// expectation readable. Both are injected, which is the property that
    /// matters.
    struct FixedRng(u8);

    impl Rng for FixedRng {
        fn next_u32(&mut self) -> u32 {
            u32::from_le_bytes([self.0; 4])
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.0);
        }
    }

    /// Decodes one of the fixture base64 strings, with the line-continuation
    /// whitespace of the literal removed.
    ///
    /// The constants above are wrapped with `\` continuations to stay inside
    /// the 80-column limit, which leaves leading spaces in the string; base64
    /// has no whitespace, so stripping it recovers the fixture's exact bytes.
    fn fixture(encoded: &str) -> Vec<u8> {
        let tight: Vec<u8> = encoded
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        base64::decode(&tight).expect("the fixture base64 is well formed")
    }

    /// A little-endian `u16` from a decoded message, for reading a security
    /// buffer back out.
    fn le16(message: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([message[at], message[at + 1]])
    }

    /// A little-endian `u32` from a decoded message.
    fn le32(message: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([
            message[at],
            message[at + 1],
            message[at + 2],
            message[at + 3],
        ])
    }

    /// The `(length, allocated, offset)` triplet of the security buffer at
    /// `at`.
    fn security_buffer_at(message: &[u8], at: usize) -> (u16, u16, u32) {
        (
            le16(message, at),
            le16(message, at + 2),
            le32(message, at + 4),
        )
    }

    /// A [`NtlmData`] carrying `flags`, `challenge` and `target_info`.
    ///
    /// Built through the public decode path where possible; this constructor
    /// exists for the cases that need a state no well-formed type-2 message
    /// produces.
    fn state_with(
        flags: u32,
        challenge: [u8; CHALLENGE_LEN],
        target_info: Option<Vec<u8>>,
    ) -> NtlmData {
        NtlmData {
            flags: NtlmFlags::from_bits(flags),
            nonce: challenge,
            target_info,
        }
    }

    /// A well-formed type-2 message carrying `flags` and `challenge`, with no
    /// Target Information block.
    ///
    /// 32 bytes: the shortest message the validation accepts.
    fn minimal_type2(flags: u32, challenge: [u8; CHALLENGE_LEN]) -> Vec<u8> {
        let mut message = Vec::with_capacity(32);
        message.extend_from_slice(&NTLMSSP_SIGNATURE);
        message.extend_from_slice(&TYPE2_MARKER);
        message.extend_from_slice(&security_buffer(0, 0));
        message.extend_from_slice(&flags.to_le_bytes());
        message.extend_from_slice(&challenge);
        assert_eq!(message.len(), 32);
        message
    }

    // -----------------------------------------------------------------------
    // Constants and the flag table.
    // -----------------------------------------------------------------------

    #[test]
    fn the_signature_is_eight_bytes_and_ends_in_a_nul() {
        // `lib/vauth/ntlm.c:45` writes seven bytes of text and relies on the
        // terminator; `:364` compares eight. Both halves are asserted here
        // because a seven-byte constant would shift every field by one.
        assert_eq!(NTLMSSP_SIGNATURE.len(), 8);
        assert_eq!(&NTLMSSP_SIGNATURE[..7], b"NTLMSSP");
        assert_eq!(NTLMSSP_SIGNATURE[7], 0x00);
        assert_eq!(
            NTLMSSP_SIGNATURE,
            [0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00]
        );
    }

    #[test]
    fn the_frozen_constants_hold_their_c_values() {
        assert_eq!(NTLM_BUFSIZE, 1024, "lib/vauth/ntlm.c:48");
        assert_eq!(TYPE1_SIZE, 32, "lib/vauth/ntlm.c:500");
        assert_eq!(TYPE3_HEADER_SIZE, 64, "lib/vauth/ntlm.c:761");
        assert_eq!(RESPONSE_LEN, 24, "0x18, lib/vauth/ntlm.c:728");
        assert_eq!(CHALLENGE_LEN, 8, "lib/vauth/vauth.h:182");
        assert_eq!(HASH_KEY_LEN, 21, "lib/curl_ntlm_core.c:308-310");
        assert_eq!(LM_PASSWORD_MAX, 14, "lib/curl_ntlm_core.c:360");
        assert_eq!(CURL_MAX_INPUT_LENGTH, 8_000_000);
        assert_eq!(TYPE3_WORKSTATION, b"WORKSTATION");
        assert_eq!(TYPE3_WORKSTATION.len(), 11, "sizeof(host) - 1");
        assert_eq!(NTLM_SCHEME, "NTLM");
        assert_eq!(DEFAULT_SERVICE, "HTTP", "lib/http_ntlm.c:146");
        assert_eq!(LM_HASH_MAGIC, *b"KGS!@#$%", "lib/curl_ntlm_core.c:358");
        assert_eq!(TYPE1_MARKER, [0x01, 0x00, 0x00, 0x00]);
        assert_eq!(TYPE2_MARKER, [0x02, 0x00, 0x00, 0x00]);
        assert_eq!(TYPE3_MARKER, [0x03, 0x00, 0x00, 0x00]);
        assert_eq!(NTLMV2_BLOB_SIGNATURE, [0x01, 0x01, 0x00, 0x00]);
        assert_eq!(FILETIME_EPOCH_BIAS_SECS, 11_644_473_600);
        assert_eq!(FILETIME_TICKS_PER_SEC, 10_000_000);
    }

    #[test]
    fn every_flag_is_the_bit_lib_vauth_ntlm_c_defines() {
        // `lib/vauth/ntlm.c:53-159`, bit by bit. Written as shifts rather than
        // as hexadecimal so that a transposed pair is visible.
        assert_eq!(NTLMFLAG_NEGOTIATE_UNICODE, 1 << 0);
        assert_eq!(NTLMFLAG_NEGOTIATE_OEM, 1 << 1);
        assert_eq!(NTLMFLAG_REQUEST_TARGET, 1 << 2);
        assert_eq!(NTLMFLAG_NEGOTIATE_SIGN, 1 << 4);
        assert_eq!(NTLMFLAG_NEGOTIATE_SEAL, 1 << 5);
        assert_eq!(NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE, 1 << 6);
        assert_eq!(NTLMFLAG_NEGOTIATE_LM_KEY, 1 << 7);
        assert_eq!(NTLMFLAG_NEGOTIATE_NTLM_KEY, 1 << 9);
        assert_eq!(NTLMFLAG_NEGOTIATE_ANONYMOUS, 1 << 11);
        assert_eq!(NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED, 1 << 12);
        assert_eq!(NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED, 1 << 13);
        assert_eq!(NTLMFLAG_NEGOTIATE_LOCAL_CALL, 1 << 14);
        assert_eq!(NTLMFLAG_NEGOTIATE_ALWAYS_SIGN, 1 << 15);
        assert_eq!(NTLMFLAG_TARGET_TYPE_DOMAIN, 1 << 16);
        assert_eq!(NTLMFLAG_TARGET_TYPE_SERVER, 1 << 17);
        assert_eq!(NTLMFLAG_TARGET_TYPE_SHARE, 1 << 18);
        assert_eq!(NTLMFLAG_NEGOTIATE_NTLM2_KEY, 1 << 19);
        assert_eq!(NTLMFLAG_REQUEST_INIT_RESPONSE, 1 << 20);
        assert_eq!(NTLMFLAG_REQUEST_ACCEPT_RESPONSE, 1 << 21);
        assert_eq!(NTLMFLAG_REQUEST_NONNT_SESSION_KEY, 1 << 22);
        assert_eq!(NTLMFLAG_NEGOTIATE_TARGET_INFO, 1 << 23);
        assert_eq!(NTLMFLAG_NEGOTIATE_128, 1 << 29);
        assert_eq!(NTLMFLAG_NEGOTIATE_KEY_EXCHANGE, 1 << 30);
        assert_eq!(NTLMFLAG_NEGOTIATE_56, 1 << 31);
    }

    #[test]
    fn the_flag_table_is_ordered_and_has_no_duplicate() {
        let mut previous = 0u32;
        for (bit, name) in FLAG_NAMES {
            assert!(
                bit > previous,
                "{name} is out of ascending bit order or repeated"
            );
            assert_eq!(bit.count_ones(), 1, "{name} names more than one bit");
            previous = bit;
        }
        assert_eq!(FLAG_NAMES.len(), 24, "24 of the 32 bits carry names");
    }

    #[test]
    fn the_type_one_flag_word_is_the_five_bits_and_their_sum() {
        // `lib/vauth/ntlm.c:480-484`, the five names in the C's own order.
        assert_eq!(
            TYPE1_FLAGS,
            NTLMFLAG_NEGOTIATE_OEM
                | NTLMFLAG_REQUEST_TARGET
                | NTLMFLAG_NEGOTIATE_NTLM_KEY
                | NTLMFLAG_NEGOTIATE_NTLM2_KEY
                | NTLMFLAG_NEGOTIATE_ALWAYS_SIGN
        );

        // The value, as a literal, and its little-endian encoding -- which is
        // what the two fixtures compare.
        assert_eq!(TYPE1_FLAGS, 0x0008_8206);
        assert_eq!(longquartet(TYPE1_FLAGS), [0x06, 0x82, 0x08, 0x00]);
    }

    // -----------------------------------------------------------------------
    // The little-endian helpers.
    // -----------------------------------------------------------------------

    #[test]
    fn shortpair_and_longquartet_are_little_endian() {
        // `SHORTPAIR(x)` = `x & 0xff`, `(x >> 8) & 0xff`.
        assert_eq!(shortpair(0), [0x00, 0x00]);
        assert_eq!(shortpair(0x18), [0x18, 0x00]);
        assert_eq!(shortpair(64), [0x40, 0x00]);
        assert_eq!(shortpair(0x1234), [0x34, 0x12]);
        assert_eq!(shortpair(0xffff), [0xff, 0xff]);

        // `LONGQUARTET(x)`, four bytes.
        assert_eq!(longquartet(0), [0, 0, 0, 0]);
        assert_eq!(longquartet(0x0102_0304), [0x04, 0x03, 0x02, 0x01]);
        assert_eq!(longquartet(u32::MAX), [0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn shortpair_truncates_exactly_as_the_c_macro_does() {
        // The one value the C can reach that does not fit: `ntresplen` is
        // `48 + target_info_len` and `target_info_len` is a `u16`, so it can
        // reach 65,583. C's macro keeps the low two bytes; so does this.
        assert_eq!(shortpair(0x1_0000), [0x00, 0x00]);
        assert_eq!(shortpair(0x1_0001), [0x01, 0x00]);
        assert_eq!(shortpair(65_583), [0x2f, 0x00], "48 + 65535");
        assert_eq!(shortpair(0xdead_beef), [0xef, 0xbe]);
    }

    #[test]
    fn a_security_buffer_is_length_allocated_offset_and_two_zeroes() {
        // `SHORTPAIR(len), SHORTPAIR(len), SHORTPAIR(off), 0x0, 0x0`.
        assert_eq!(
            security_buffer(0x18, 64),
            [0x18, 0x00, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00]
        );
        assert_eq!(security_buffer(0, 0), [0; 8]);
        assert_eq!(
            security_buffer(11, 120),
            [0x0b, 0x00, 0x0b, 0x00, 0x78, 0x00, 0x00, 0x00]
        );
        // Length and allocated size are always equal in curl's messages.
        let buffer = security_buffer(8, 112);
        assert_eq!(&buffer[0..2], &buffer[2..4]);
    }

    #[test]
    fn the_readers_are_the_inverse_of_the_writers() {
        assert_eq!(read16_le([0x34, 0x12]), 0x1234);
        assert_eq!(read32_le([0x86, 0x82, 0x01, 0x00]), FIXTURE_TYPE2_FLAGS);
        for value in [0u16, 1, 0x18, 64, 0xff00, u16::MAX] {
            let bytes = shortpair(usize::from(value));
            assert_eq!(read16_le(bytes), value);
        }
        for value in [0u32, 1, TYPE1_FLAGS, FIXTURE_TYPE2_FLAGS, u32::MAX] {
            assert_eq!(read32_le(longquartet(value)), value);
        }
    }

    // -----------------------------------------------------------------------
    // String widening. The naivety is the contract.
    // -----------------------------------------------------------------------

    #[test]
    fn widening_interleaves_zeroes_and_is_not_utf_16() {
        // `dest[2 * i] = src[i]; dest[2 * i + 1] = '\0';`
        assert_eq!(unicodecpy(b"AB"), vec![b'A', 0, b'B', 0]);
        assert_eq!(unicodecpy(b""), Vec::<u8>::new());
        assert_eq!(unicodecpy(b"testuser").len(), 16);

        // A byte at or above 0x80 is copied THROUGH, paired with a zero. A
        // UTF-16 encoder handed the same input as text would produce
        // something else entirely -- for the two bytes below, either one unit
        // (0x00E4) if read as UTF-8, or a replacement character. The naive
        // form is what curl emits and what a server verifies against.
        assert_eq!(unicodecpy(&[0xC3, 0xA4]), vec![0xC3, 0x00, 0xA4, 0x00]);
        assert_eq!(unicodecpy(&[0x80]), vec![0x80, 0x00]);
        assert_eq!(unicodecpy(&[0xFF]), vec![0xFF, 0x00]);

        // An interior NUL widens like any other byte: there is no terminator
        // to stop at, which is why the function takes a length in C and a
        // slice here.
        assert_eq!(unicodecpy(&[b'a', 0, b'b']), vec![b'a', 0, 0, 0, b'b', 0]);
    }

    #[test]
    fn only_the_uppercasing_widener_folds_case_and_only_over_ascii() {
        assert_eq!(ascii_uppercase_to_unicode_le(b"user"), unicodecpy(b"USER"));
        assert_eq!(ascii_uppercase_to_unicode_le(b"USER"), unicodecpy(b"USER"));

        // `Curl_raw_toupper` leaves 0x80..=0xFF untouched, so a high byte is
        // not folded by some locale's idea of case.
        assert_eq!(
            ascii_uppercase_to_unicode_le(&[0xE4, b'a']),
            vec![0xE4, 0x00, b'A', 0x00]
        );

        // Digits and punctuation pass through.
        assert_eq!(ascii_uppercase_to_unicode_le(b"a1-"), unicodecpy(b"A1-"));
    }

    #[test]
    fn copying_and_widening_are_the_two_arms_of_the_string_writes() {
        assert_eq!(copy_bytes(b"testuser"), b"testuser".to_vec());
        assert_eq!(widen_or_copy(b"ab", false), b"ab".to_vec());
        assert_eq!(widen_or_copy(b"ab", true), vec![b'a', 0, b'b', 0]);
        assert_eq!(widen_or_copy(b"ab", true).len(), 2 * b"ab".len());
    }

    #[test]
    fn blanks_are_spaces_and_tabs_and_nothing_else() {
        // `ISBLANK`, not `ISSPACE`: a newline or carriage return must NOT be
        // skipped, or a folded header would parse differently.
        assert_eq!(pass_blanks(b"   x"), b"x");
        assert_eq!(pass_blanks(b"\t\t x"), b"x");
        assert_eq!(pass_blanks(b"x  "), b"x  ");
        assert_eq!(pass_blanks(b""), b"");
        assert_eq!(pass_blanks(b"    "), b"");
        assert_eq!(pass_blanks(b"\nx"), b"\nx");
        assert_eq!(pass_blanks(b"\rx"), b"\rx");
    }

    // -----------------------------------------------------------------------
    // The primitives, against MS-NLMP section 4.2 and the C's structure.
    // -----------------------------------------------------------------------

    /// The published NTOWFv1 of `"Password"`: MS-NLMP 4.2.2.1.2.
    #[rustfmt::skip]
    const MSNLMP_NTOWFV1: [u8; 16] = [
        0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca,
        0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8, 0x52,
    ];

    /// The published LMOWFv1 of `"Password"`: MS-NLMP 4.2.2.1.1.
    #[rustfmt::skip]
    const MSNLMP_LMOWFV1: [u8; 16] = [
        0xe5, 0x2c, 0xac, 0x67, 0x41, 0x9a, 0x9a, 0x22,
        0x4a, 0x3b, 0x10, 0x8f, 0x3f, 0xa6, 0xcb, 0x6d,
    ];

    /// The published NTOWFv2 for user `"User"`, domain `"Domain"`, password
    /// `"Password"`: MS-NLMP 4.2.4.1.1.
    #[rustfmt::skip]
    const MSNLMP_NTOWFV2: [u8; 16] = [
        0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93,
        0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f,
    ];

    /// The published server challenge: MS-NLMP 4.2.1.
    #[rustfmt::skip]
    const MSNLMP_SERVER_CHALLENGE: [u8; 8] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    /// The published client challenge: MS-NLMP 4.2.1.
    const MSNLMP_CLIENT_CHALLENGE: [u8; 8] = [0xaa; 8];

    #[test]
    fn the_nt_hash_matches_the_published_vector_and_does_not_fold_case() {
        let hash = mk_nt_hash(b"Password").expect("a short password");
        assert_eq!(&hash.0[..16], &MSNLMP_NTOWFV1);

        // NOT upper-cased, unlike the LM hash. If it were, these would agree.
        let folded = mk_nt_hash(b"PASSWORD").expect("a short password");
        assert_ne!(hash.0, folded.0, "mk_nt_hash must not fold case");

        // Bytes 16 through 20 are the third DES key and must be zero:
        // `memset(ntbuffer + 16, 0, 21 - 16)`.
        assert_eq!(&hash.0[16..21], &[0u8; 5]);
        assert_eq!(hash.0.len(), 21);
    }

    #[test]
    fn the_lm_hash_matches_the_published_vector_and_folds_case() {
        let hash = mk_lm_hash(b"Password");
        assert_eq!(&hash.0[..16], &MSNLMP_LMOWFV1);

        // `Curl_strntoupper`: LM is case-insensitive, so all three agree.
        assert_eq!(mk_lm_hash(b"PASSWORD").0, hash.0);
        assert_eq!(mk_lm_hash(b"password").0, hash.0);

        assert_eq!(&hash.0[16..21], &[0u8; 5], "the third key is zero");
    }

    #[test]
    fn the_lm_hash_truncates_at_fourteen_bytes_and_pads_shorter_ones() {
        // `CURLMIN(strlen(password), 14)`: byte 15 onwards cannot matter.
        let fourteen = mk_lm_hash(b"12345678901234");
        assert_eq!(mk_lm_hash(b"123456789012345").0, fourteen.0);
        assert_eq!(mk_lm_hash(b"12345678901234EXTRA").0, fourteen.0);

        // `memset(&pw[len], 0, 14 - len)`: the padding is key material, so a
        // one-byte password is not the same as an empty one.
        assert_ne!(mk_lm_hash(b"").0, mk_lm_hash(b"a").0);

        // The empty password still produces the two encryptions of the magic
        // under an all-zero key, which is a well-known constant rather than
        // zeroes.
        assert_ne!(&mk_lm_hash(b"").0[..16], &[0u8; 16]);
    }

    #[test]
    fn the_lm_hash_encrypts_the_magic_and_is_not_keyed_by_it() {
        // The direction trap: the PASSWORD is the key and `KGS!@#$%` is the
        // plaintext. Reversing them is the second-most-copied NTLM bug, and
        // this asserts the halves independently of `mk_lm_hash`.
        let hash = mk_lm_hash(b"Password");

        let mut padded = [0u8; 14];
        padded[..8].copy_from_slice(b"PASSWORD");

        let mut first = [0u8; 7];
        first.copy_from_slice(&padded[..7]);
        let mut second = [0u8; 7];
        second.copy_from_slice(&padded[7..14]);

        assert_eq!(
            &hash.0[0..8],
            &des_ecb_encrypt(&first, &LM_HASH_MAGIC),
            "bytes 0..8 are DES(key = pw[0..7], plaintext = magic)"
        );
        assert_eq!(
            &hash.0[8..16],
            &des_ecb_encrypt(&second, &LM_HASH_MAGIC),
            "bytes 8..16 are DES(key = pw[7..14], plaintext = magic)"
        );
    }

    #[test]
    fn an_absurd_password_length_is_rejected_out_of_memory() {
        // `if(len > SIZE_MAX / 2) return CURLE_OUT_OF_MEMORY;`
        // (`lib/curl_ntlm_core.c:416`). A password of that length cannot be
        // constructed, so the guard is exercised from the reachable side: a
        // long-but-sane password succeeds, and the widening really does double
        // the length the guard protects against.
        let long = vec![b'x'; 4096];
        assert!(mk_nt_hash(&long).is_ok());
        assert_eq!(unicodecpy(&long).len(), 2 * long.len());
        assert!(
            mk_nt_hash(b"").is_ok(),
            "the empty password is not rejected"
        );
    }

    #[test]
    fn odd_parity_makes_every_byte_have_an_odd_population() {
        // `curl_des_set_odd_parity`, `lib/curl_ntlm_core.c:142-158`.
        for value in 0u8..=255 {
            let mut block = [value; 8];
            set_odd_parity(&mut block);
            for byte in block {
                assert_eq!(
                    byte.count_ones() % 2,
                    1,
                    "0x{value:02x} was adjusted to 0x{byte:02x}"
                );
                // Only bit 0 may change, which is the bit DES discards.
                assert_eq!(byte & 0xfe, value & 0xfe);
            }
        }

        // Spot checks in both directions: 0x00 has no set bits so bit 0 is
        // set; 0x01 already has one so bit 0 is left alone; 0x03 has two so
        // bit 0 is cleared.
        let mut block = [0x00, 0x01, 0x03, 0x07, 0xff, 0xfe, 0x80, 0x81];
        set_odd_parity(&mut block);
        assert_eq!(block, [0x01, 0x01, 0x02, 0x07, 0xfe, 0xfe, 0x80, 0x80]);
    }

    #[test]
    fn the_key_extension_matches_the_c_shift_chain_bit_for_bit() {
        // Recomputed here from the C's eight expressions, independently of
        // `extend_key_56_to_64`, with the parity step applied afterwards --
        // which is the order every `setup_des_key` arm uses.
        #[rustfmt::skip]
        #[allow(clippy::identity_op)] // The C's masks, kept verbatim.
        fn reference(k: &[u8; 7]) -> [u8; 8] {
            let mut key = [
                k[0],
                ((k[0] << 7) & 0xFF) | (k[1] >> 1),
                ((k[1] << 6) & 0xFF) | (k[2] >> 2),
                ((k[2] << 5) & 0xFF) | (k[3] >> 3),
                ((k[3] << 4) & 0xFF) | (k[4] >> 4),
                ((k[4] << 3) & 0xFF) | (k[5] >> 5),
                ((k[5] << 2) & 0xFF) | (k[6] >> 6),
                 (k[6] << 1) & 0xFF,
            ];
            set_odd_parity(&mut key);
            key
        }

        for seed in 0u8..=255 {
            let input = [
                seed,
                seed.wrapping_add(1),
                seed.wrapping_mul(3),
                seed ^ 0x5a,
                seed.wrapping_sub(7),
                !seed,
                seed.rotate_left(3),
            ];
            assert_eq!(extend_key_56_to_64(&input), reference(&input));
        }

        // The all-zero key spreads to eight zero bytes, which parity then
        // turns into eight 0x01s. Written as a literal so the chain has one
        // fully worked example.
        assert_eq!(extend_key_56_to_64(&[0; 7]), [0x01; 8]);

        // The first output byte is the first input byte, save for parity.
        let extended = extend_key_56_to_64(&[0xfe, 0, 0, 0, 0, 0, 0]);
        assert_eq!(extended[0] & 0xfe, 0xfe);
    }

    #[test]
    fn lm_resp_is_three_independent_encryptions_of_the_same_plaintext() {
        // `lib/curl_ntlm_core.c:308-310`: "The 8 byte plaintext is encrypted
        // with each key and the resulting 24 bytes are stored". NOT chained,
        // and NOT Triple DES.
        let hash = mk_nt_hash(b"Password").expect("a short password");
        let response = lm_resp(&hash, &MSNLMP_SERVER_CHALLENGE);

        assert_eq!(response.len(), 24);
        assert_eq!(
            &response[0..8],
            &des_ecb_encrypt(&hash.key(0), &MSNLMP_SERVER_CHALLENGE)
        );
        assert_eq!(
            &response[8..16],
            &des_ecb_encrypt(&hash.key(1), &MSNLMP_SERVER_CHALLENGE)
        );
        assert_eq!(
            &response[16..24],
            &des_ecb_encrypt(&hash.key(2), &MSNLMP_SERVER_CHALLENGE)
        );

        // The three keys are the three seven-byte windows of the buffer.
        assert_eq!(hash.key(0), hash.0[0..7]);
        assert_eq!(hash.key(1), hash.0[7..14]);
        assert_eq!(hash.key(2), hash.0[14..21]);
    }

    #[test]
    fn the_ntlmv1_responses_match_the_published_vectors() {
        // MS-NLMP 4.2.2.2.1 (NTLMv1 response) and 4.2.2.2.2 (LM response),
        // both over the published challenge with password "Password".
        #[rustfmt::skip]
        const NT: [u8; 24] = [
            0x67, 0xc4, 0x30, 0x11, 0xf3, 0x02, 0x98, 0xa2,
            0xad, 0x35, 0xec, 0xe6, 0x4f, 0x16, 0x33, 0x1c,
            0x44, 0xbd, 0xbe, 0xd9, 0x27, 0x84, 0x1f, 0x94,
        ];
        #[rustfmt::skip]
        const LM: [u8; 24] = [
            0x98, 0xde, 0xf7, 0xb8, 0x7f, 0x88, 0xaa, 0x5d,
            0xaf, 0xe2, 0xdf, 0x77, 0x96, 0x88, 0xa1, 0x72,
            0xde, 0xf1, 0x1c, 0x7d, 0x5c, 0xcd, 0xef, 0x13,
        ];

        let nt_hash = mk_nt_hash(b"Password").expect("a short password");
        assert_eq!(lm_resp(&nt_hash, &MSNLMP_SERVER_CHALLENGE), NT);

        let lm_hash = mk_lm_hash(b"Password");
        assert_eq!(lm_resp(&lm_hash, &MSNLMP_SERVER_CHALLENGE), LM);
    }

    #[test]
    fn the_v2_hash_matches_the_published_vector() {
        let nt_hash = mk_nt_hash(b"Password").expect("a short password");
        let v2 = mk_ntlmv2_hash(b"User", b"Domain", &nt_hash)
            .expect("short identity");
        assert_eq!(v2, MSNLMP_NTOWFV2);
    }

    #[test]
    fn the_v2_hash_folds_the_user_and_not_the_domain() {
        // `lib/curl_ntlm_core.c:521-522`, two different wideners one line
        // apart. This is the classic NTLMv2 implementation bug, so it is
        // asserted from three directions.
        let nt_hash = mk_nt_hash(b"Password").expect("a short password");

        let lower = mk_ntlmv2_hash(b"user", b"Domain", &nt_hash).expect("ok");
        let upper = mk_ntlmv2_hash(b"USER", b"Domain", &nt_hash).expect("ok");
        assert_eq!(lower, upper, "the USER is folded, so these must agree");

        let domain_lower =
            mk_ntlmv2_hash(b"User", b"domain", &nt_hash).expect("ok");
        let domain_upper =
            mk_ntlmv2_hash(b"User", b"DOMAIN", &nt_hash).expect("ok");
        assert_ne!(
            domain_lower, domain_upper,
            "the DOMAIN is not folded, so these must differ"
        );

        // And the input really is `uppercase(user) || domain`, keyed by the
        // first sixteen bytes of the NT hash -- not the whole 21.
        let mut identity = ascii_uppercase_to_unicode_le(b"User");
        identity.extend_from_slice(&unicodecpy(b"Domain"));
        assert_eq!(
            mk_ntlmv2_hash(b"User", b"Domain", &nt_hash).expect("ok"),
            hmac_md5(&nt_hash.0[..16], &identity)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "allocates 8 MB to stand past the limit")]
    fn an_oversized_identity_is_rejected_out_of_memory_not_too_large() {
        // `lib/curl_ntlm_core.c:512-513` returns CURLE_OUT_OF_MEMORY for a
        // length check. The code a caller observes is frozen, so the
        // surprising choice is asserted rather than tidied.
        //
        // One buffer serves all three cases -- two rejections and the
        // acceptance one byte below -- because the C's test is on the length
        // and a sub-slice has the length it needs.
        let nt_hash = mk_nt_hash(b"Password").expect("a short password");
        let huge = vec![b'x'; CURL_MAX_INPUT_LENGTH + 1];

        assert_eq!(
            mk_ntlmv2_hash(&huge, b"Domain", &nt_hash),
            Err(CURLcode::OutOfMemory),
            "an oversized username"
        );
        assert_eq!(
            mk_ntlmv2_hash(b"User", &huge, &nt_hash),
            Err(CURLcode::OutOfMemory),
            "an oversized domain"
        );

        // Exactly at the limit is accepted: the C's test is `>`, not `>=`.
        assert!(mk_ntlmv2_hash(
            b"User",
            &huge[..CURL_MAX_INPUT_LENGTH],
            &nt_hash
        )
        .is_ok());
    }

    #[test]
    fn the_lmv2_response_puts_the_server_challenge_first() {
        // `lib/curl_ntlm_core.c:650-651`. Reversing the two produces a
        // well-formed response that authenticates nothing, so the order is
        // asserted against an independently computed HMAC.
        let nt_hash = mk_nt_hash(b"Password").expect("a short password");
        let v2 = mk_ntlmv2_hash(b"User", b"Domain", &nt_hash).expect("ok");

        let response = mk_lmv2_resp(
            &v2,
            &MSNLMP_CLIENT_CHALLENGE,
            &MSNLMP_SERVER_CHALLENGE,
        );

        let mut expected_input = [0u8; 16];
        expected_input[0..8].copy_from_slice(&MSNLMP_SERVER_CHALLENGE);
        expected_input[8..16].copy_from_slice(&MSNLMP_CLIENT_CHALLENGE);
        assert_eq!(&response[0..16], &hmac_md5(&v2, &expected_input));

        // The trailing eight bytes are the CLIENT challenge, which is what
        // lets the server verify the response.
        assert_eq!(&response[16..24], &MSNLMP_CLIENT_CHALLENGE);
        assert_eq!(response.len(), 24);

        // The published LMv2 response of MS-NLMP 4.2.4.2.1.
        #[rustfmt::skip]
        const PUBLISHED: [u8; 16] = [
            0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10,
            0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc, 0xcc, 0x19,
        ];
        assert_eq!(&response[0..16], &PUBLISHED);

        // Swapping the arguments changes the answer, which is what makes the
        // order load-bearing rather than incidental.
        let swapped = mk_lmv2_resp(
            &v2,
            &MSNLMP_SERVER_CHALLENGE,
            &MSNLMP_CLIENT_CHALLENGE,
        );
        assert_ne!(response, swapped);
    }

    // -----------------------------------------------------------------------
    // The FILETIME conversion and the NTLMv2 blob.
    // -----------------------------------------------------------------------

    #[test]
    fn the_filetime_of_the_unix_epoch_is_the_forced_timestamp() {
        // `time2filetime(&tw, (time_t)0)`, which is what `CURL_FORCETIME`
        // selects: (0 + 11644473600) * 10000000 = 116444736000000000.
        let filetime = time2filetime(0);
        let ticks = 11_644_473_600u64 * 10_000_000;
        assert_eq!(u64::from(filetime.low), ticks & 0xFFFF_FFFF);
        assert_eq!(u64::from(filetime.high), ticks >> 32);
        assert_eq!(ticks, 116_444_736_000_000_000);

        // The eight wire bytes are the little-endian 64-bit value.
        assert_eq!(filetime.to_le_bytes(), ticks.to_le_bytes());
    }

    #[test]
    fn the_filetime_follows_the_c_formula_across_the_range() {
        for seconds in [0i64, 1, 1_000_000_000, 1_700_000_000, -1, -100] {
            let expected = seconds
                .checked_add_unsigned(FILETIME_EPOCH_BIAS_SECS)
                .expect("well inside range")
                .max(0);
            let ticks = u64::try_from(expected).expect("non-negative")
                * FILETIME_TICKS_PER_SEC;
            assert_eq!(
                time2filetime(seconds).to_le_bytes(),
                ticks.to_le_bytes()
            );
        }

        // A clock set before 1601 clamps at zero rather than wrapping, and one
        // set absurdly far ahead saturates. Neither is reachable from a real
        // clock; both are reachable from an injected one, and a panic inside
        // an authentication exchange is not an acceptable answer.
        assert_eq!(time2filetime(i64::MIN), MsFiletime { low: 0, high: 0 });
        let saturated = time2filetime(i64::MAX);
        assert_eq!(saturated.low, u32::MAX);
        assert_eq!(saturated.high, u32::MAX);
    }

    #[test]
    fn the_v2_response_has_the_documented_layout_and_hmac() {
        let target_info = vec![0xABu8; 40];
        let ntlm = state_with(
            NTLMFLAG_NEGOTIATE_NTLM2_KEY | NTLMFLAG_NEGOTIATE_TARGET_INFO,
            MSNLMP_SERVER_CHALLENGE,
            Some(target_info.clone()),
        );
        let nt_hash = mk_nt_hash(b"Password").expect("a short password");
        let v2 = mk_ntlmv2_hash(b"User", b"Domain", &nt_hash).expect("ok");

        let clock = TestClock::default();
        let response =
            mk_ntlmv2_resp(&v2, &MSNLMP_CLIENT_CHALLENGE, &ntlm, &clock);

        // `len = HMAC_MD5_LENGTH + NTLMv2_BLOB_LEN` with
        // `NTLMv2_BLOB_LEN = 44 - 16 + target_info_len + 4`.
        let blob_len = 32 + target_info.len();
        assert_eq!(blob_len, 72);
        assert_eq!(response.len(), 16 + blob_len);

        // The blob's fields, at response offsets.
        assert_eq!(&response[16..20], &NTLMV2_BLOB_SIGNATURE);
        assert_eq!(&response[20..24], &[0u8; 4], "reserved");
        assert_eq!(
            &response[24..32],
            &time2filetime(0).to_le_bytes(),
            "the default TestClock reads the Unix epoch"
        );
        assert_eq!(&response[32..40], &MSNLMP_CLIENT_CHALLENGE);
        assert_eq!(&response[40..44], &[0u8; 4], "unknown");
        assert_eq!(&response[44..44 + target_info.len()], &target_info[..]);
        assert_eq!(&response[44 + target_info.len()..], &[0u8; 4], "unknown");

        // The HMAC is over `server_challenge || blob`, which is what C's
        // write-into-offset-8 achieves. Recomputed here from the response's
        // own blob, so the assertion does not restate the assembly.
        let blob = &response[16..];
        let mut hmac_input = Vec::new();
        hmac_input.extend_from_slice(&MSNLMP_SERVER_CHALLENGE);
        hmac_input.extend_from_slice(blob);
        assert_eq!(&response[0..16], &hmac_md5(&v2, &hmac_input));
        assert_eq!(hmac_input.len(), blob_len + 8);
    }

    #[test]
    fn the_v2_response_without_target_info_is_forty_eight_bytes() {
        let ntlm = state_with(
            NTLMFLAG_NEGOTIATE_NTLM2_KEY,
            MSNLMP_SERVER_CHALLENGE,
            None,
        );
        let nt_hash = mk_nt_hash(b"Password").expect("a short password");
        let v2 = mk_ntlmv2_hash(b"User", b"", &nt_hash).expect("ok");

        let response = mk_ntlmv2_resp(
            &v2,
            &MSNLMP_CLIENT_CHALLENGE,
            &ntlm,
            &TestClock::default(),
        );

        assert_eq!(response.len(), 48, "16 + 32 + 0");
        assert_eq!(&response[44..48], &[0u8; 4], "the trailing unknown four");
    }

    #[test]
    fn the_v2_response_timestamp_follows_the_injected_clock() {
        let ntlm =
            state_with(NTLMFLAG_NEGOTIATE_NTLM2_KEY, FIXTURE_CHALLENGE, None);
        let nt_hash = mk_nt_hash(b"pw").expect("a short password");
        let v2 = mk_ntlmv2_hash(b"u", b"d", &nt_hash).expect("ok");

        let clock = TestClock::default();
        clock.set_epoch_secs(1_700_000_000);
        let moved =
            mk_ntlmv2_resp(&v2, &MSNLMP_CLIENT_CHALLENGE, &ntlm, &clock);
        assert_eq!(&moved[24..32], &time2filetime(1_700_000_000).to_le_bytes());

        // And a clock reading zero reproduces `CURL_FORCETIME` exactly, which
        // is the seam the harness sets. Two different clocks, two different
        // responses, no global in either.
        let forced = mk_ntlmv2_resp(
            &v2,
            &MSNLMP_CLIENT_CHALLENGE,
            &ntlm,
            &TestClock::default(),
        );
        assert_eq!(&forced[24..32], &time2filetime(0).to_le_bytes());
        assert_ne!(moved, forced);
    }

    // -----------------------------------------------------------------------
    // The type-1 message.
    // -----------------------------------------------------------------------

    #[test]
    fn the_type1_message_is_the_thirty_two_bytes_the_fixtures_expect() {
        // THE most valuable assertion about outbound bytes in this file:
        // `tests/data/test1008:108` and `tests/data/test1021:118`, literally.
        let mut ntlm = NtlmData::new();
        let message = create_type1_message(&mut ntlm);

        assert_eq!(message.len(), 32);
        assert_eq!(message.as_slice(), &FIXTURE_TYPE1[..]);

        // Field by field, so a failure names the field rather than the blob.
        assert_eq!(&message[0..8], &NTLMSSP_SIGNATURE);
        assert_eq!(&message[8..12], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(&message[12..16], &[0x06, 0x82, 0x08, 0x00]);
        assert_eq!(
            &message[16..32],
            &[0u8; 16],
            "twenty zeroes, less the four"
        );
        assert_eq!(&message[12..32].len(), &20);

        // The two security buffers are empty and point at zero.
        assert_eq!(security_buffer_at(&message, 16), (0, 0, 0));
        assert_eq!(security_buffer_at(&message, 24), (0, 0, 0));
    }

    #[test]
    fn the_type1_message_carries_no_identity_at_all() {
        // `(void)userp; (void)passwdp; (void)service; (void)hostname;`
        // (`lib/vauth/ntlm.c:456-459`). The function takes no identity, so the
        // property is asserted the only way it can be: the message is the same
        // 32 bytes whatever state it is composed from, and contains no text.
        let mut fresh = NtlmData::new();
        let mut used = state_with(
            FIXTURE_TYPE2_FLAGS,
            FIXTURE_CHALLENGE,
            Some(vec![0x11; 16]),
        );

        assert_eq!(
            create_type1_message(&mut fresh),
            create_type1_message(&mut used)
        );

        // No hostname leaks: the message holds no printable byte beyond the
        // signature. `Curl_gethostname` is never called from this module.
        let message = create_type1_message(&mut fresh);
        assert!(!message[8..].iter().any(u8::is_ascii_alphanumeric));
    }

    #[test]
    fn composing_a_type1_message_clears_only_the_target_info() {
        // `Curl_auth_cleanup_ntlm(ntlm)` at `:462`, whose body clears the
        // block and NOTHING else -- the flag word and challenge survive, which
        // is deliberate in the C and is what a restarted handshake relies on.
        let mut ntlm = state_with(
            FIXTURE_TYPE2_FLAGS,
            FIXTURE_CHALLENGE,
            Some(vec![0x22; 8]),
        );

        let _message = create_type1_message(&mut ntlm);

        assert_eq!(ntlm.target_info(), b"");
        assert_eq!(ntlm.target_info_len(), 0);
        assert_eq!(ntlm.flags().bits(), FIXTURE_TYPE2_FLAGS, "flags survive");
        assert_eq!(ntlm.nonce(), &FIXTURE_CHALLENGE, "the challenge survives");
    }

    // -----------------------------------------------------------------------
    // The type-2 message.
    // -----------------------------------------------------------------------

    #[test]
    fn the_fixture_type2_message_decodes_to_its_flags_and_challenge() {
        let type2 = fixture(FIXTURE_TYPE2_B64);
        assert_eq!(type2.len(), 160);

        let mut ntlm = NtlmData::new();
        let (result, _) = with_tracer(|tracer| {
            decode_type2_message(&mut ntlm, &type2, tracer)
        });
        assert_eq!(result, Ok(()));

        assert_eq!(ntlm.flags().bits(), FIXTURE_TYPE2_FLAGS);
        assert_eq!(ntlm.nonce(), &FIXTURE_CHALLENGE);

        // Bit 19 is CLEAR in this fixture, which is why the corpus exercises
        // NTLMv1 and why the whole exchange is deterministic.
        assert!(
            !ntlm.flags().contains(NTLMFLAG_NEGOTIATE_NTLM2_KEY),
            "test1008 clears bit 19"
        );
        assert!(!ntlm.flags().contains(NTLMFLAG_NEGOTIATE_UNICODE));
        assert!(ntlm.flags().contains(NTLMFLAG_NEGOTIATE_OEM));

        // Bit 23 is clear TOO, so the Target Information block the message
        // carries is NOT extracted. Both halves are asserted: the flag, and
        // the block that is present in the bytes and absent from the state.
        assert!(!ntlm.flags().contains(NTLMFLAG_NEGOTIATE_TARGET_INFO));
        assert_eq!(le16(&type2, 40), 110, "the buffer declares 110 bytes");
        assert_eq!(le32(&type2, 44), 50, "at offset 50");
        assert_eq!(ntlm.target_info_len(), 0, "and curl reads none of them");

        // The six bits the flag word actually holds, named.
        for bit in [
            NTLMFLAG_NEGOTIATE_OEM,
            NTLMFLAG_REQUEST_TARGET,
            NTLMFLAG_NEGOTIATE_LM_KEY,
            NTLMFLAG_NEGOTIATE_NTLM_KEY,
            NTLMFLAG_NEGOTIATE_ALWAYS_SIGN,
            NTLMFLAG_TARGET_TYPE_DOMAIN,
        ] {
            assert!(ntlm.flags().contains(bit), "0x{bit:x}");
        }
        assert_eq!(
            NTLMFLAG_NEGOTIATE_OEM
                | NTLMFLAG_REQUEST_TARGET
                | NTLMFLAG_NEGOTIATE_LM_KEY
                | NTLMFLAG_NEGOTIATE_NTLM_KEY
                | NTLMFLAG_NEGOTIATE_ALWAYS_SIGN
                | NTLMFLAG_TARGET_TYPE_DOMAIN,
            FIXTURE_TYPE2_FLAGS,
            "those six and no others"
        );
    }

    #[test]
    fn each_of_the_three_validations_rejects_with_one_code_and_one_line() {
        let good = minimal_type2(0, FIXTURE_CHALLENGE);

        // 1. `type2len < 32`. Every shorter length, including empty.
        for length in 0..32 {
            let mut ntlm = NtlmData::new();
            let (result, log) = with_tracer(|tracer| {
                decode_type2_message(&mut ntlm, &good[..length], tracer)
            });
            assert_eq!(
                result,
                Err(CURLcode::BadContentEncoding),
                "a {length}-byte message must be rejected"
            );
            assert!(log.contains(BAD_TYPE2));
        }

        // 2. A wrong signature -- including a wrong EIGHTH byte, which a
        // seven-byte comparison would accept.
        for index in 0..8 {
            let mut broken = good.clone();
            broken[index] ^= 0xff;
            let mut ntlm = NtlmData::new();
            let (result, log) = with_tracer(|tracer| {
                decode_type2_message(&mut ntlm, &broken, tracer)
            });
            assert_eq!(
                result,
                Err(CURLcode::BadContentEncoding),
                "byte {index} of the signature must be checked"
            );
            assert!(log.contains(BAD_TYPE2));
        }

        // 3. A wrong message type, in each of its four bytes.
        for index in 8..12 {
            let mut broken = good.clone();
            broken[index] ^= 0xff;
            let mut ntlm = NtlmData::new();
            let (result, _) = with_tracer(|tracer| {
                decode_type2_message(&mut ntlm, &broken, tracer)
            });
            assert_eq!(result, Err(CURLcode::BadContentEncoding));
        }

        // The 32-byte message itself is accepted, so the loop above is
        // discriminating rather than rejecting everything.
        let mut ntlm = NtlmData::new();
        assert_eq!(
            quietly(|tracer| decode_type2_message(&mut ntlm, &good, tracer)),
            Ok(())
        );
    }

    #[test]
    fn the_flag_word_is_cleared_before_validation_not_after() {
        // `ntlm->flags = 0;` at `:361`, ABOVE the validation. A rejected
        // message must leave no flags behind, so that a caller which ignores
        // the error cannot compose a message keyed on stale terms.
        let mut ntlm = state_with(
            NTLMFLAG_NEGOTIATE_NTLM2_KEY | NTLMFLAG_NEGOTIATE_UNICODE,
            FIXTURE_CHALLENGE,
            None,
        );
        assert_ne!(ntlm.flags(), NtlmFlags::NONE);

        let (result, _) = with_tracer(|tracer| {
            decode_type2_message(&mut ntlm, b"short", tracer)
        });

        assert_eq!(result, Err(CURLcode::BadContentEncoding));
        assert_eq!(
            ntlm.flags(),
            NtlmFlags::NONE,
            "flags cleared before the check"
        );
        assert_eq!(ntlm.flags().bits(), 0);
    }

    #[test]
    fn target_info_is_extracted_only_when_bit_twenty_three_is_set() {
        // `if(ntlm->flags & NTLMFLAG_NEGOTIATE_TARGET_INFO)` (`:374`). The
        // fixture message CARRIES a 110-byte block at offset 50 and declares
        // it in the security buffer at offset 40 -- and curl reads none of it,
        // because the server left bit 23 clear. Same bytes, both answers, so
        // the assertion is about the flag and not about the message.
        let type2 = fixture(FIXTURE_TYPE2_B64);
        assert_eq!(
            FIXTURE_TYPE2_FLAGS & NTLMFLAG_NEGOTIATE_TARGET_INFO,
            0,
            "test1008's server leaves bit 23 clear"
        );
        assert_eq!(le16(&type2, 40), 110, "yet the buffer declares a block");
        assert_eq!(le32(&type2, 44), 50);

        let mut without = NtlmData::new();
        assert_eq!(
            quietly(|tracer| decode_type2_message(
                &mut without,
                &type2,
                tracer
            )),
            Ok(())
        );
        assert_eq!(without.target_info_len(), 0, "not extracted");
        assert_eq!(without.flags().bits(), FIXTURE_TYPE2_FLAGS);

        // Setting the bit on the same message extracts it.
        let mut announced = type2.clone();
        let set = FIXTURE_TYPE2_FLAGS | NTLMFLAG_NEGOTIATE_TARGET_INFO;
        announced[20..24].copy_from_slice(&set.to_le_bytes());

        let mut with = NtlmData::new();
        assert_eq!(
            quietly(|tracer| decode_type2_message(
                &mut with, &announced, tracer
            )),
            Ok(())
        );
        assert_eq!(with.target_info_len(), 110);
        assert_eq!(with.target_info(), &type2[50..160]);
    }

    #[test]
    fn every_target_info_bound_is_enforced() {
        // The three disjuncts of `lib/vauth/ntlm.c:269-271`, each on its own.
        let build = |len: u16, offset: u32| -> Vec<u8> {
            let mut message = Vec::new();
            message.extend_from_slice(&NTLMSSP_SIGNATURE);
            message.extend_from_slice(&TYPE2_MARKER);
            message.extend_from_slice(&security_buffer(0, 0));
            message.extend_from_slice(
                &NTLMFLAG_NEGOTIATE_TARGET_INFO.to_le_bytes(),
            );
            message.extend_from_slice(&FIXTURE_CHALLENGE);
            message.extend_from_slice(&[0u8; 8]); // context
            message.extend_from_slice(&len.to_le_bytes()); // 40
            message.extend_from_slice(&len.to_le_bytes()); // 42
            message.extend_from_slice(&offset.to_le_bytes()); // 44
            assert_eq!(message.len(), 48);
            message.extend_from_slice(&[0x5au8; 16]); // data block
            message
        };

        let reject = |message: &[u8], why: &str| {
            let mut ntlm = NtlmData::new();
            let (result, log) = with_tracer(|tracer| {
                decode_type2_message(&mut ntlm, message, tracer)
            });
            assert_eq!(result, Err(CURLcode::BadContentEncoding), "{why}");
            assert!(log.contains(BAD_TYPE2_TARGET_INFO), "{why}: diagnostic");
            // C emits the general line a SECOND time from the caller (`:377`).
            assert!(log.contains(BAD_TYPE2), "{why}: the second line");
        };

        // (a) `target_info_offset > type2len`: 64 offset into a 64-byte
        // message is exactly the boundary, so 65 is the first rejection.
        let message = build(4, 65);
        assert_eq!(message.len(), 64);
        reject(&message, "an offset past the end");

        // (b) `(target_info_offset + target_info_len) > type2len`.
        reject(&build(20, 48), "a block that runs off the end");

        // (c) `target_info_offset < 48`: pointing back into the header.
        reject(&build(4, 47), "an offset inside the fixed header");
        reject(&build(4, 0), "a zero offset");

        // An offset of exactly 48 with a block that fits is ACCEPTED, so the
        // three rejections above are about their bounds and not about the
        // shape of the message.
        let good = build(16, 48);
        let mut ntlm = NtlmData::new();
        assert_eq!(
            quietly(|tracer| decode_type2_message(&mut ntlm, &good, tracer)),
            Ok(())
        );
        assert_eq!(ntlm.target_info(), &[0x5au8; 16]);
    }

    #[test]
    fn a_zero_length_block_and_a_short_message_both_leave_no_block() {
        // `ntlm->target_info_len = target_info_len;` at `:285` is
        // unconditional, so both of these paths clear any earlier block rather
        // than retaining it.
        let mut short =
            minimal_type2(NTLMFLAG_NEGOTIATE_TARGET_INFO, FIXTURE_CHALLENGE);
        assert_eq!(short.len(), 32, "below the 48 the fields need");

        let mut ntlm = state_with(0, [0; 8], Some(vec![0x33; 4]));
        assert_eq!(
            quietly(|tracer| decode_type2_message(&mut ntlm, &short, tracer)),
            Ok(())
        );
        assert_eq!(ntlm.target_info_len(), 0, "a short message leaves none");

        // A 48-byte message declaring a zero-length block: the fields are read
        // and `if(target_info_len > 0)` fails.
        short.extend_from_slice(&[0u8; 16]);
        assert_eq!(short.len(), 48);
        let mut ntlm = state_with(0, [0; 8], Some(vec![0x33; 4]));
        assert_eq!(
            quietly(|tracer| decode_type2_message(&mut ntlm, &short, tracer)),
            Ok(())
        );
        assert_eq!(ntlm.target_info_len(), 0, "a zero length leaves none");
    }

    #[test]
    fn a_second_type2_message_replaces_the_first_block() {
        // "replace any previous data" (`:277`). The fixture message with bit
        // 23 set, so that the extraction runs at all.
        let mut type2 = fixture(FIXTURE_TYPE2_B64);
        let announced = FIXTURE_TYPE2_FLAGS | NTLMFLAG_NEGOTIATE_TARGET_INFO;
        type2[20..24].copy_from_slice(&announced.to_le_bytes());

        let mut ntlm = state_with(0, [0; 8], Some(vec![0xEEu8; 200]));
        assert_eq!(
            quietly(|tracer| decode_type2_message(&mut ntlm, &type2, tracer)),
            Ok(())
        );
        assert_eq!(ntlm.target_info_len(), 110);
        assert!(!ntlm.target_info().contains(&0xEE));
    }

    #[test]
    fn a_rejected_block_leaves_an_earlier_one_intact() {
        // The asymmetry of `lib/vauth/ntlm.c:274`: the bounds failure returns
        // BEFORE `ntlm->target_info_len = target_info_len`, so an earlier block
        // survives, where a short message or a zero length discards it.
        let mut type2 = fixture(FIXTURE_TYPE2_B64);
        let announced = FIXTURE_TYPE2_FLAGS | NTLMFLAG_NEGOTIATE_TARGET_INFO;
        type2[20..24].copy_from_slice(&announced.to_le_bytes());
        // An offset inside the fixed header: rejection (c).
        type2[44..48].copy_from_slice(&0u32.to_le_bytes());

        let mut ntlm = state_with(0, [0; 8], Some(vec![0xEEu8; 12]));
        assert_eq!(
            quietly(|tracer| decode_type2_message(&mut ntlm, &type2, tracer)),
            Err(CURLcode::BadContentEncoding)
        );
        assert_eq!(ntlm.target_info_len(), 12, "the earlier block survives");
        assert_eq!(ntlm.target_info(), &[0xEEu8; 12]);
    }

    // -----------------------------------------------------------------------
    // The username and domain split.
    // -----------------------------------------------------------------------

    #[test]
    fn the_user_splits_on_a_backslash_before_a_slash() {
        // `strchr(userp, '\\')` first, `strchr(userp, '/')` only if that
        // found nothing (`lib/vauth/ntlm.c:593-595`).
        assert_eq!(split_user(b"dom\\user"), (&b"dom"[..], &b"user"[..]));
        assert_eq!(split_user(b"dom/user"), (&b"dom"[..], &b"user"[..]));

        // No separator: the domain is EMPTY, never the whole string.
        assert_eq!(split_user(b"user"), (&b""[..], &b"user"[..]));
        assert_eq!(split_user(b""), (&b""[..], &b""[..]));

        // Precedence, which is observable: with both present the BACKSLASH
        // wins wherever it sits, so the slash ends up inside the domain.
        assert_eq!(split_user(b"a/b\\c"), (&b"a/b"[..], &b"c"[..]));
        assert_eq!(split_user(b"a\\b/c"), (&b"a"[..], &b"b/c"[..]));

        // `strchr` finds the FIRST occurrence, so a second separator stays in
        // the user part.
        assert_eq!(split_user(b"a\\b\\c"), (&b"a"[..], &b"b\\c"[..]));
        assert_eq!(split_user(b"a/b/c"), (&b"a"[..], &b"b/c"[..]));

        // Degenerate positions: `user++` steps over the separator, so it
        // appears in neither part.
        assert_eq!(split_user(b"\\user"), (&b""[..], &b"user"[..]));
        assert_eq!(split_user(b"dom\\"), (&b"dom"[..], &b""[..]));
    }

    // -----------------------------------------------------------------------
    // The type-3 message. The fixture comparison is the single most valuable
    // assertion in this file.
    // -----------------------------------------------------------------------

    /// Composes the type-3 message `tests/data/test1008` expects, from that
    /// fixture's own type-2 message and credentials.
    fn fixture_type3() -> Vec<u8> {
        let type2 = fixture(FIXTURE_TYPE2_B64);
        let mut ntlm = NtlmData::new();
        quietly(|tracer| decode_type2_message(&mut ntlm, &type2, tracer))
            .expect("the fixture type-2 message is well formed");

        let mut rng = FixedRng(0);
        let clock = TestClock::default();
        quietly(|tracer| {
            create_type3_message(
                &mut ntlm,
                FIXTURE_USER,
                FIXTURE_PASSWORD,
                &mut rng,
                &clock,
                tracer,
            )
        })
        .expect("the fixture exchange succeeds")
    }

    #[test]
    fn the_type3_message_is_byte_for_byte_what_test1008_expects() {
        // THE assertion. `tests/data/test1008:113` and
        // `tests/data/test1021:123` carry the same expected base64; it is
        // decoded here and compared whole, exactly as `compareparts` does.
        let expected = fixture(FIXTURE_TYPE3_B64);
        assert_eq!(expected.len(), 131);

        let produced = fixture_type3();
        assert_eq!(produced, expected);
    }

    #[test]
    fn the_type3_header_fields_are_the_fixtures_own() {
        let message = fixture_type3();

        assert_eq!(&message[0..8], &NTLMSSP_SIGNATURE);
        assert_eq!(&message[8..12], &[0x03, 0x00, 0x00, 0x00]);

        // (length, allocated, offset) for each of the six security buffers,
        // read back out of the produced message and compared against the
        // numbers decoded from the fixture.
        assert_eq!(security_buffer_at(&message, 12), (24, 24, 64), "LM");
        assert_eq!(security_buffer_at(&message, 20), (24, 24, 88), "NT");
        assert_eq!(security_buffer_at(&message, 28), (0, 0, 112), "domain");
        assert_eq!(security_buffer_at(&message, 36), (8, 8, 112), "user");
        assert_eq!(security_buffer_at(&message, 44), (11, 11, 120), "host");
        assert_eq!(security_buffer_at(&message, 52), (0, 0, 0), "session key");

        // `userlen` is 8 and not 16, and `hostlen` 11 and not 22, so this
        // message is NOT Unicode -- which is what bit 0 being clear means.
        assert_eq!(le16(&message, 36), 8);
        assert_eq!(le16(&message, 44), 11);

        // The flag word at offset 60, and the fixture's own value.
        assert_eq!(le32(&message, 60), FIXTURE_TYPE2_FLAGS);
        assert_eq!(&message[60..64], &[0x86, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn the_type3_message_ends_with_the_username_then_workstation() {
        // `dGVzdHVzZXJXT1JLU1RBVElPTg` decodes to `testuser` + `WORKSTATION`.
        let message = fixture_type3();
        assert_eq!(&message[112..120], FIXTURE_USER);
        assert_eq!(&message[120..131], TYPE3_WORKSTATION);
        assert_eq!(&message[112..], b"testuserWORKSTATION");

        // The hostname is the CONSTANT, not this machine's name.
        assert_eq!(TYPE3_WORKSTATION, b"WORKSTATION");
    }

    #[test]
    fn the_type3_responses_are_the_fixtures_own_bytes() {
        // Decoded from `tests/data/test1008:113`, written as literals.
        #[rustfmt::skip]
        const LMRESP: [u8; 24] = [
            0x5a, 0x64, 0x43, 0x02, 0x91, 0x09, 0x91, 0x4c,
            0x86, 0x38, 0xf4, 0xb7, 0x0e, 0x3b, 0xc0, 0x48,
            0xca, 0x1d, 0x11, 0xe5, 0xbf, 0x37, 0xf1, 0x41,
        ];
        #[rustfmt::skip]
        const NTRESP: [u8; 24] = [
            0xa9, 0x85, 0x72, 0x17, 0x8c, 0xba, 0xff, 0x2f,
            0xfb, 0x17, 0xaa, 0xa6, 0x11, 0x0e, 0xe5, 0x5e,
            0x35, 0xc5, 0x17, 0x7b, 0x47, 0xd7, 0x5e, 0x39,
        ];

        let message = fixture_type3();
        assert_eq!(&message[64..88], &LMRESP);
        assert_eq!(&message[88..112], &NTRESP);

        // And they are what the primitives produce independently, which ties
        // the fixture to the algorithm rather than to this assembly.
        let nt_hash = mk_nt_hash(FIXTURE_PASSWORD).expect("short password");
        let lm_hash = mk_lm_hash(FIXTURE_PASSWORD);
        assert_eq!(lm_resp(&nt_hash, &FIXTURE_CHALLENGE), NTRESP);
        assert_eq!(lm_resp(&lm_hash, &FIXTURE_CHALLENGE), LMRESP);
    }

    #[test]
    fn the_type3_message_is_deterministic_with_no_entropy_or_clock() {
        // The corpus exercises NTLMv1, which is DES over the server challenge
        // alone. Two runs with DIFFERENT generators and DIFFERENT clocks must
        // agree, which is what makes byte-exact fixture comparison possible.
        let type2 = fixture(FIXTURE_TYPE2_B64);

        let compose = |seed: u8, epoch: i64| -> Vec<u8> {
            let mut ntlm = NtlmData::new();
            quietly(|t| decode_type2_message(&mut ntlm, &type2, t))
                .expect("well formed");
            let mut rng = FixedRng(seed);
            let clock = TestClock::default();
            clock.set_epoch_secs(epoch);
            quietly(|t| {
                create_type3_message(
                    &mut ntlm,
                    FIXTURE_USER,
                    FIXTURE_PASSWORD,
                    &mut rng,
                    &clock,
                    t,
                )
            })
            .expect("succeeds")
        };

        assert_eq!(compose(0x00, 0), compose(0xff, 1_700_000_000));
    }

    #[test]
    fn the_version_one_path_clears_bit_nineteen_from_the_emitted_flags() {
        // `ntlm->flags &= ~NTLMFLAG_NEGOTIATE_NTLM2_KEY;` (`:662`). Start from
        // a type-2 message that DOES set the bit, then clear it artificially
        // in the state to force the version-1 branch, and confirm the emitted
        // word has it clear -- and, separately, that a state which keeps it
        // takes the other branch.
        let flags = NTLMFLAG_NEGOTIATE_OEM | NTLMFLAG_NEGOTIATE_NTLM2_KEY;
        let mut ntlm = state_with(flags, FIXTURE_CHALLENGE, None);
        assert!(ntlm.flags().contains(NTLMFLAG_NEGOTIATE_NTLM2_KEY));

        let mut rng = FixedRng(0xaa);
        let clock = TestClock::default();
        let v2_message = quietly(|t| {
            create_type3_message(&mut ntlm, b"u", b"pw", &mut rng, &clock, t)
        })
        .expect("succeeds");

        // The version-2 branch does NOT clear the bit.
        assert_eq!(
            le32(&v2_message, 60) & NTLMFLAG_NEGOTIATE_NTLM2_KEY,
            NTLMFLAG_NEGOTIATE_NTLM2_KEY
        );

        // The version-1 branch does.
        let mut v1_state =
            state_with(NTLMFLAG_NEGOTIATE_OEM, FIXTURE_CHALLENGE, None);
        let v1_message = quietly(|t| {
            create_type3_message(
                &mut v1_state,
                b"u",
                b"pw",
                &mut rng,
                &clock,
                t,
            )
        })
        .expect("succeeds");
        assert_eq!(le32(&v1_message, 60), NTLMFLAG_NEGOTIATE_OEM);
        assert_eq!(v1_state.flags().bits(), NTLMFLAG_NEGOTIATE_OEM);

        // A state that already had the bit clear is unchanged by the clear.
        let fixture_message = fixture_type3();
        assert_eq!(le32(&fixture_message, 60), FIXTURE_TYPE2_FLAGS);
    }

    #[test]
    fn bit_nineteen_selects_the_version_and_the_response_length_with_it() {
        // With the bit set the NT slot holds an NTLMv2 response of
        // `48 + target_info_len` bytes; with it clear, 24.
        let target_info = vec![0x77u8; 24];
        let mut v2 = state_with(
            NTLMFLAG_NEGOTIATE_NTLM2_KEY | NTLMFLAG_NEGOTIATE_TARGET_INFO,
            FIXTURE_CHALLENGE,
            Some(target_info.clone()),
        );
        let mut rng = FixedRng(0xaa);
        let clock = TestClock::default();

        let message = quietly(|t| {
            create_type3_message(&mut v2, b"User", b"pw", &mut rng, &clock, t)
        })
        .expect("succeeds");

        let ntresplen = 48 + target_info.len();
        assert_eq!(ntresplen, 72);
        assert_eq!(
            security_buffer_at(&message, 20),
            (72, 72, 88),
            "the NT buffer describes the v2 response"
        );

        // THE LM BUFFER IS STILL 0x18, in the version-2 path too: the literal
        // `SHORTPAIR(0x18)` of `:728-730`, not a length derived from anything.
        assert_eq!(security_buffer_at(&message, 12), (0x18, 0x18, 64));

        // And the offsets that follow are pushed out by the longer response.
        assert_eq!(security_buffer_at(&message, 28), (0, 0, 88 + 72));
        assert_eq!(message.len(), 88 + 72 + 4 + 11);

        // The v2 blob sits at the NT offset and carries its signature.
        assert_eq!(&message[88 + 16..88 + 20], &NTLMV2_BLOB_SIGNATURE);
        assert_eq!(&message[88 + 32..88 + 40], &[0xaa; 8], "client nonce");
        assert_eq!(&message[88 + 44..88 + 44 + 24], &target_info[..]);

        // With the bit clear the same state produces a 24-byte NT slot.
        let mut v1 = state_with(0, FIXTURE_CHALLENGE, None);
        let v1_message = quietly(|t| {
            create_type3_message(&mut v1, b"User", b"pw", &mut rng, &clock, t)
        })
        .expect("succeeds");
        assert_eq!(security_buffer_at(&v1_message, 20), (24, 24, 88));
    }

    #[test]
    fn the_lm_offset_is_always_sixty_four_and_the_session_key_always_zero() {
        // `lmrespoff = 64` (`:675`) with no dependence on anything, and the
        // session-key buffer written as four literal zero pairs (`:754-757`).
        let mut rng = FixedRng(0x11);
        let clock = TestClock::default();

        for flags in [
            0,
            NTLMFLAG_NEGOTIATE_UNICODE,
            NTLMFLAG_NEGOTIATE_NTLM2_KEY,
            NTLMFLAG_NEGOTIATE_NTLM2_KEY | NTLMFLAG_NEGOTIATE_UNICODE,
        ] {
            let mut ntlm =
                state_with(flags, FIXTURE_CHALLENGE, Some(vec![0x5a; 8]));
            let message = quietly(|t| {
                create_type3_message(
                    &mut ntlm,
                    b"dom\\user",
                    b"pw",
                    &mut rng,
                    &clock,
                    t,
                )
            })
            .expect("succeeds");

            assert_eq!(le32(&message, 16), 64, "flags 0x{flags:x}: LM offset");
            assert_eq!(
                le16(&message, 12),
                0x18,
                "flags 0x{flags:x}: LM length"
            );
            assert_eq!(&message[52..60], &[0u8; 8], "flags 0x{flags:x}: key");
            assert_eq!(le32(&message, 24), 88, "flags 0x{flags:x}: NT offset");
        }
    }

    #[test]
    fn the_unicode_flag_doubles_every_string_and_widens_it() {
        // `if(unicode) { domlen *= 2; userlen *= 2; hostlen *= 2; }` BEFORE
        // the offsets (`:669-679`).
        let mut ntlm =
            state_with(NTLMFLAG_NEGOTIATE_UNICODE, FIXTURE_CHALLENGE, None);
        let mut rng = FixedRng(0);
        let clock = TestClock::default();

        let message = quietly(|t| {
            create_type3_message(
                &mut ntlm,
                b"DOM\\user",
                b"pw",
                &mut rng,
                &clock,
                t,
            )
        })
        .expect("succeeds");

        // 3 -> 6, 4 -> 8, 11 -> 22, and the offsets follow the doubled
        // lengths rather than the original ones.
        assert_eq!(security_buffer_at(&message, 28), (6, 6, 112), "domain");
        assert_eq!(security_buffer_at(&message, 36), (8, 8, 118), "user");
        assert_eq!(security_buffer_at(&message, 44), (22, 22, 126), "host");
        assert_eq!(message.len(), 126 + 22);

        // The strings themselves are widened, naively.
        assert_eq!(&message[112..118], &unicodecpy(b"DOM")[..]);
        assert_eq!(&message[118..126], &unicodecpy(b"user")[..]);
        assert_eq!(&message[126..148], &unicodecpy(TYPE3_WORKSTATION)[..]);
    }

    #[test]
    fn a_domain_qualified_user_splits_across_two_security_buffers() {
        let mut ntlm = state_with(0, FIXTURE_CHALLENGE, None);
        let mut rng = FixedRng(0);
        let clock = TestClock::default();

        let message = quietly(|t| {
            create_type3_message(
                &mut ntlm,
                b"WORKGROUP\\alice",
                b"pw",
                &mut rng,
                &clock,
                t,
            )
        })
        .expect("succeeds");

        assert_eq!(security_buffer_at(&message, 28), (9, 9, 112), "domain");
        assert_eq!(security_buffer_at(&message, 36), (5, 5, 121), "user");
        assert_eq!(security_buffer_at(&message, 44), (11, 11, 126), "host");
        assert_eq!(&message[112..121], b"WORKGROUP");
        assert_eq!(&message[121..126], b"alice");
        assert_eq!(&message[126..], TYPE3_WORKSTATION);
    }

    #[test]
    fn an_oversized_v2_response_is_rejected_with_the_first_guard() {
        // `if(ntresplen + size > sizeof(ntlmbuf))` (`:776-780`) with `size` at
        // 88, so `ntresplen > 936`, that is `target_info_len > 888`.
        let mut rng = FixedRng(0);
        let clock = TestClock::default();

        let mut too_big = state_with(
            NTLMFLAG_NEGOTIATE_NTLM2_KEY | NTLMFLAG_NEGOTIATE_TARGET_INFO,
            FIXTURE_CHALLENGE,
            Some(vec![0x5a; 889]),
        );
        let (result, log) = with_tracer(|t| {
            create_type3_message(&mut too_big, b"u", b"pw", &mut rng, &clock, t)
        });
        assert_eq!(result, Err(CURLcode::TooLarge));
        assert!(log.contains(MESSAGE_TOO_BIG), "{log}");

        // 888 is accepted, so the boundary is exactly where the C puts it:
        // 88 + 48 + 888 == 1024.
        let mut at_limit = state_with(
            NTLMFLAG_NEGOTIATE_NTLM2_KEY | NTLMFLAG_NEGOTIATE_TARGET_INFO,
            FIXTURE_CHALLENGE,
            Some(vec![0x5a; 888]),
        );
        let boundary = quietly(|t| {
            create_type3_message(&mut at_limit, b"", b"pw", &mut rng, &clock, t)
        });
        // The message now fills the buffer exactly, so the SECOND guard
        // rejects it as soon as any string is appended -- which is itself the
        // behaviour under test in the next case. With no user, no domain and
        // an 11-byte host it is still over.
        assert_eq!(boundary, Err(CURLcode::TooLarge));
    }

    #[test]
    fn an_oversized_identity_is_rejected_with_the_second_guard() {
        // `if(size + userlen + domlen + hostlen >= NTLM_BUFSIZE)`
        // (`:799-803`). Note `>=`: filling the buffer exactly is a rejection.
        let mut rng = FixedRng(0);
        let clock = TestClock::default();

        // size is 112 after an NTLMv1 message's header and two responses, so
        // the identity budget is 1024 - 112 - 11 = 901 bytes.
        let mut ntlm = state_with(0, FIXTURE_CHALLENGE, None);
        let user = vec![b'u'; 902];
        let (result, log) = with_tracer(|t| {
            create_type3_message(&mut ntlm, &user, b"pw", &mut rng, &clock, t)
        });
        assert_eq!(result, Err(CURLcode::TooLarge));
        assert!(log.contains(IDENTITY_TOO_BIG), "{log}");

        // One byte under the boundary succeeds, so the guard is about the
        // length and not about the message.
        let mut ntlm = state_with(0, FIXTURE_CHALLENGE, None);
        let user = vec![b'u'; 900];
        let message = quietly(|t| {
            create_type3_message(&mut ntlm, &user, b"pw", &mut rng, &clock, t)
        })
        .expect("900 + 11 + 112 == 1023, one below the bound");
        assert_eq!(message.len(), 1023);
    }

    #[test]
    fn a_type3_message_cleans_up_on_both_the_success_and_the_error_path() {
        // `error:` at `:832` is reached by both `goto`s AND by falling off the
        // success path, and calls `Curl_auth_cleanup_ntlm` either way.
        let mut rng = FixedRng(0);
        let clock = TestClock::default();

        let mut succeeding = state_with(
            NTLMFLAG_NEGOTIATE_TARGET_INFO,
            FIXTURE_CHALLENGE,
            Some(vec![0x5a; 16]),
        );
        assert_eq!(succeeding.target_info_len(), 16);
        assert!(quietly(|t| create_type3_message(
            &mut succeeding,
            b"u",
            b"pw",
            &mut rng,
            &clock,
            t
        ))
        .is_ok());
        assert_eq!(succeeding.target_info_len(), 0, "cleared on success");

        let mut failing = state_with(
            NTLMFLAG_NEGOTIATE_NTLM2_KEY | NTLMFLAG_NEGOTIATE_TARGET_INFO,
            FIXTURE_CHALLENGE,
            Some(vec![0x5a; 1000]),
        );
        assert_eq!(
            quietly(|t| create_type3_message(
                &mut failing,
                b"u",
                b"pw",
                &mut rng,
                &clock,
                t
            )),
            Err(CURLcode::TooLarge)
        );
        assert_eq!(failing.target_info_len(), 0, "cleared on error too");

        // The flag word survives both, as `Curl_auth_cleanup_ntlm` intends.
        assert_ne!(failing.flags(), NtlmFlags::NONE);
    }

    // -----------------------------------------------------------------------
    // The state machine and the HTTP glue.
    // -----------------------------------------------------------------------

    #[test]
    fn the_five_states_are_in_the_c_declaration_order() {
        // `lib/urldata.h:312-318`. The order is what makes
        // `*state >= NTLMSTATE_TYPE1` (`lib/http_ntlm.c:99`) mean "in the
        // middle of a handshake", so it is asserted rather than assumed.
        assert!(NtlmState::None < NtlmState::Type1);
        assert!(NtlmState::Type1 < NtlmState::Type2);
        assert!(NtlmState::Type2 < NtlmState::Type3);
        assert!(NtlmState::Type3 < NtlmState::Last);
        assert_eq!(NtlmState::default(), NtlmState::None, "the calloced value");

        // The comparison the C makes, spelled out: exactly the two middle
        // states satisfy it once `Last` and `Type3` have been excluded.
        assert!(NtlmState::Type1 >= NtlmState::Type1);
        assert!(NtlmState::Type2 >= NtlmState::Type1);
        assert!(!(NtlmState::None >= NtlmState::Type1));
    }

    #[test]
    fn a_connection_keeps_the_two_sides_apart() {
        // `conn->http_ntlm_state` and `conn->proxy_ntlm_state` are two
        // fields, and the two metadata entries are two entries.
        let mut conn = NtlmConnection::new();
        assert_eq!(conn.state(false), NtlmState::None);
        assert_eq!(conn.state(true), NtlmState::None);
        assert!(conn.peek(false).is_none());
        assert!(conn.peek(true).is_none());

        *conn.state_mut(true) = NtlmState::Type2;
        assert_eq!(conn.state(true), NtlmState::Type2);
        assert_eq!(
            conn.state(false),
            NtlmState::None,
            "the origin is separate"
        );

        conn.data_mut(true).nonce = FIXTURE_CHALLENGE;
        assert_eq!(
            conn.peek(true).map(|data| *data.nonce()),
            Some(FIXTURE_CHALLENGE)
        );
        assert!(conn.peek(false).is_none(), "the origin block is separate");

        // `Curl_auth_ntlm_remove` drops the data and LEAVES the state.
        conn.remove(true);
        assert!(conn.peek(true).is_none());
        assert_eq!(conn.state(true), NtlmState::Type2, "state untouched");
    }

    #[test]
    fn a_non_ntlm_header_is_ignored_without_error() {
        // The whole C body is inside `if(checkprefix("NTLM", header))`
        // (`lib/http_ntlm.c:63`).
        let mut conn = NtlmConnection::new();
        for header in [
            &b"Basic realm=\"x\""[..],
            &b"Negotiate"[..],
            &b""[..],
            &b"NTL"[..],
        ] {
            assert_eq!(
                quietly(|t| input_ntlm(&mut conn, false, header, t)),
                Ok(())
            );
        }
        assert_eq!(conn.state(false), NtlmState::None, "nothing advanced");

        // `checkprefix` folds case, so a lowercase scheme IS matched.
        assert_eq!(
            quietly(|t| input_ntlm(&mut conn, false, b"ntlm", t)),
            Ok(())
        );
        assert_eq!(conn.state(false), NtlmState::Type1);
    }

    #[test]
    fn a_longer_scheme_token_is_this_functions_callers_problem() {
        // `Curl_input_ntlm` guards on `checkprefix`, which is a plain prefix
        // match -- so `NTLM2` DOES reach the payload path here, takes `2 abc`
        // for base64 and fails on it. That is the C's behaviour, not a defect
        // in it: the "must not be followed by an alphanumeric" rule lives in
        // `authcmp` (`lib/http.c:867-872`), which `crate::auth::input_auth`
        // applies BEFORE dispatching, so a well-formed scan never hands this
        // function such a header.
        let mut conn = NtlmConnection::new();
        assert_eq!(
            quietly(|t| input_ntlm(&mut conn, false, b"NTLM2 abc", t)),
            Err(CURLcode::BadContentEncoding)
        );
        assert_eq!(conn.state(false), NtlmState::None);

        // And the upstream guard really does reject it, so the scan cannot.
        assert!(!authcmp("NTLM", b"NTLM2 abc"));
        assert!(authcmp("NTLM", b"NTLM abc"));
        assert!(authcmp("NTLM", b"NTLM"));
    }

    #[test]
    fn a_bare_ntlm_header_moves_a_fresh_connection_to_type1() {
        let mut conn = NtlmConnection::new();
        assert_eq!(
            quietly(|t| input_ntlm(&mut conn, false, b"NTLM", t)),
            Ok(())
        );
        assert_eq!(conn.state(false), NtlmState::Type1);

        // Trailing blanks are skipped, so these are all "bare".
        for header in [&b"NTLM "[..], &b"NTLM\t"[..], &b"NTLM   "[..]] {
            let mut fresh = NtlmConnection::new();
            assert_eq!(
                quietly(|t| input_ntlm(&mut fresh, false, header, t)),
                Ok(())
            );
            assert_eq!(fresh.state(false), NtlmState::Type1);
        }
    }

    #[test]
    fn a_bare_ntlm_in_state_last_restarts_the_exchange() {
        // `infof(data, "NTLM auth restarted"); Curl_auth_ntlm_remove(...)`
        // then fall through to `*state = NTLMSTATE_TYPE1`.
        let mut conn = NtlmConnection::new();
        *conn.state_mut(false) = NtlmState::Last;
        conn.data_mut(false).nonce = FIXTURE_CHALLENGE;

        let (result, log) =
            with_tracer(|t| input_ntlm(&mut conn, false, b"NTLM", t));

        assert_eq!(result, Ok(()));
        assert!(log.contains(AUTH_RESTARTED), "{log}");
        assert_eq!(log.trim_end(), format!("* {AUTH_RESTARTED}"));
        assert_eq!(conn.state(false), NtlmState::Type1);
        assert!(conn.peek(false).is_none(), "the data block was removed");
    }

    #[test]
    fn a_bare_ntlm_in_state_type3_rejects_the_handshake() {
        // `infof("NTLM handshake rejected"); remove; *state = NTLMSTATE_NONE;`
        // then `return CURLE_REMOTE_ACCESS_DENIED`.
        let mut conn = NtlmConnection::new();
        *conn.state_mut(false) = NtlmState::Type3;
        conn.data_mut(false).nonce = FIXTURE_CHALLENGE;

        let (result, log) =
            with_tracer(|t| input_ntlm(&mut conn, false, b"NTLM", t));

        assert_eq!(result, Err(CURLcode::RemoteAccessDenied));
        assert!(log.contains(HANDSHAKE_REJECTED), "{log}");
        assert_eq!(
            conn.state(false),
            NtlmState::None,
            "this arm resets the state, unlike the next one"
        );
        assert!(conn.peek(false).is_none());
    }

    #[test]
    fn a_bare_ntlm_mid_handshake_is_an_internal_error() {
        // `else if(*state >= NTLMSTATE_TYPE1)`, which after the two arms above
        // means exactly Type1 and Type2. The state is LEFT ALONE here, which
        // is the difference from the Type3 arm.
        for state in [NtlmState::Type1, NtlmState::Type2] {
            let mut conn = NtlmConnection::new();
            *conn.state_mut(false) = state;
            conn.data_mut(false).nonce = FIXTURE_CHALLENGE;

            let (result, log) =
                with_tracer(|t| input_ntlm(&mut conn, false, b"NTLM", t));

            assert_eq!(result, Err(CURLcode::RemoteAccessDenied), "{state:?}");
            assert!(log.contains(HANDSHAKE_INTERNAL_ERROR), "{log}");
            assert_eq!(conn.state(false), state, "the state is not reset");
            assert!(conn.peek(false).is_some(), "the data is not removed");
        }
    }

    #[test]
    fn a_type2_payload_advances_to_type2_and_decodes() {
        let type2 = fixture(FIXTURE_TYPE2_B64);
        let encoded = base64::encode(&type2).expect("encodes");
        let header = format!("NTLM {encoded}");

        let mut conn = NtlmConnection::new();
        assert_eq!(
            quietly(|t| input_ntlm(&mut conn, true, header.as_bytes(), t)),
            Ok(())
        );

        assert_eq!(conn.state(true), NtlmState::Type2);
        let data = conn.peek(true).expect("the block was created");
        assert_eq!(data.flags().bits(), FIXTURE_TYPE2_FLAGS);
        assert_eq!(data.nonce(), &FIXTURE_CHALLENGE);

        // The origin side saw nothing.
        assert_eq!(conn.state(false), NtlmState::None);
        assert!(conn.peek(false).is_none());
    }

    #[test]
    fn a_payload_that_is_not_base64_is_rejected() {
        // `curlx_base64_decode` failing propagates its own error.
        let mut conn = NtlmConnection::new();
        assert_eq!(
            quietly(|t| input_ntlm(&mut conn, false, b"NTLM !!!!", t)),
            Err(CURLcode::BadContentEncoding)
        );
        assert_eq!(conn.state(false), NtlmState::None, "no advance on failure");

        // Valid base64 that is not a type-2 message is rejected by the decoder
        // instead, with the same code and the frozen diagnostic.
        let junk = base64::encode(b"not a type-2 message").expect("encodes");
        let (result, log) = with_tracer(|t| {
            input_ntlm(&mut conn, false, format!("NTLM {junk}").as_bytes(), t)
        });
        assert_eq!(result, Err(CURLcode::BadContentEncoding));
        assert!(log.contains(BAD_TYPE2), "{log}");
    }

    /// Drives [`output_ntlm`] and returns its emission plus the trace log.
    fn emit(
        conn: &mut NtlmConnection,
        picked: &mut AuthPickedInfo,
        proxy: bool,
        user: &[u8],
        password: &[u8],
    ) -> (Result<AuthEmission, CURLcode>, String) {
        let credentials = Credentials::new(Some(user), Some(password));
        let clock = TestClock::default();
        let mut rng = FixedRng(0xaa);
        with_tracer(|tracer| {
            let mut ctx = AuthContext {
                proxy,
                request_method: b"GET",
                request_target: b"/",
                clock: &clock,
                rng: &mut rng,
            };
            output_ntlm(conn, &credentials, picked, &mut ctx, tracer)
        })
    }

    #[test]
    fn the_type1_arm_emits_a_continuing_header_from_none_and_from_type1() {
        // `case NTLMSTATE_TYPE1: default:` -- one body, and `NTLMSTATE_NONE`
        // reaches it through the `default`. The header must be the fixture's
        // 32 bytes, base64-encoded, and the exchange must NOT be done.
        let expected = base64::encode(&FIXTURE_TYPE1).expect("encodes");

        for state in [NtlmState::None, NtlmState::Type1] {
            let mut conn = NtlmConnection::new();
            *conn.state_mut(true) = state;
            let mut picked = AuthPickedInfo::new();

            let (emission, _) = emit(
                &mut conn,
                &mut picked,
                true,
                FIXTURE_USER,
                FIXTURE_PASSWORD,
            );

            let emission = emission.expect("a type-1 message always composes");
            assert_eq!(
                emission,
                AuthEmission::Continuing(format!(
                    "Proxy-Authorization: NTLM {expected}\r\n"
                )),
                "from {state:?}"
            );
            assert!(!emission.is_done(), "a type-1 message continues");

            // The state is NOT advanced by emitting a type-1 message: the C
            // leaves it for the type-2 response to change.
            assert_eq!(conn.state(true), state);
            assert_eq!(picked.get(true), None, "only the LAST arm records it");
        }
    }

    #[test]
    fn the_origin_side_emits_the_unprefixed_header() {
        // `proxy ? "Proxy-" : ""` -- the one difference between the two sides.
        let mut conn = NtlmConnection::new();
        let mut picked = AuthPickedInfo::new();
        let (emission, _) = emit(
            &mut conn,
            &mut picked,
            false,
            FIXTURE_USER,
            FIXTURE_PASSWORD,
        );

        let expected = base64::encode(&FIXTURE_TYPE1).expect("encodes");
        assert_eq!(
            emission,
            Ok(AuthEmission::Continuing(format!(
                "Authorization: NTLM {expected}\r\n"
            )))
        );
    }

    #[test]
    fn the_type2_arm_emits_the_fixture_type3_header_and_is_final() {
        // The end-to-end assertion: the header line `tests/data/test1008:113`
        // expects, composed through the state machine.
        let type2 = fixture(FIXTURE_TYPE2_B64);
        let mut conn = NtlmConnection::new();
        quietly(|t| {
            let encoded = base64::encode(&type2).expect("encodes");
            input_ntlm(&mut conn, true, format!("NTLM {encoded}").as_bytes(), t)
        })
        .expect("the fixture type-2 message decodes");
        assert_eq!(conn.state(true), NtlmState::Type2);

        let mut picked = AuthPickedInfo::new();
        let (emission, _) =
            emit(&mut conn, &mut picked, true, FIXTURE_USER, FIXTURE_PASSWORD);

        // The base64 the fixture carries, verbatim.
        let expected_b64: String = FIXTURE_TYPE3_B64
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        assert_eq!(
            emission,
            Ok(AuthEmission::Final(format!(
                "Proxy-Authorization: NTLM {expected_b64}\r\n"
            )))
        );

        // `*state = NTLMSTATE_TYPE3; authp->done = TRUE;`
        assert_eq!(conn.state(true), NtlmState::Type3);
        assert!(emission.expect("emitted").is_done());
    }

    #[test]
    fn state_type3_becomes_last_before_the_switch_and_emits_nothing() {
        // `if(*state == NTLMSTATE_TYPE3) *state = NTLMSTATE_LAST;` at
        // `:192-193`, so there is no `case NTLMSTATE_TYPE3`.
        let mut conn = NtlmConnection::new();
        *conn.state_mut(false) = NtlmState::Type3;
        let mut picked = AuthPickedInfo::new();

        let (emission, log) = emit(
            &mut conn,
            &mut picked,
            false,
            FIXTURE_USER,
            FIXTURE_PASSWORD,
        );

        assert_eq!(emission, Ok(AuthEmission::Nothing), "no header at all");
        assert_eq!(conn.state(false), NtlmState::Last);
        assert!(log.is_empty(), "the LAST arm is silent: {log}");

        // "we need to set the bit by force": the only trace this arm leaves.
        assert_eq!(picked.get(false), Some(AuthMask::NTLM));
        assert_eq!(picked.get(true), None, "the proxy side is untouched");

        // And it reports done, so the transfer proceeds.
        assert!(emission.expect("emitted").is_done());
    }

    #[test]
    fn state_last_stays_last_and_keeps_emitting_nothing() {
        // A second and third request on an authenticated connection: the state
        // is already LAST, so the pre-switch transition does not apply and the
        // LAST arm runs again.
        let mut conn = NtlmConnection::new();
        *conn.state_mut(true) = NtlmState::Last;
        let mut picked = AuthPickedInfo::new();

        for _ in 0..3 {
            let (emission, _) = emit(
                &mut conn,
                &mut picked,
                true,
                FIXTURE_USER,
                FIXTURE_PASSWORD,
            );
            assert_eq!(emission, Ok(AuthEmission::Nothing));
            assert_eq!(conn.state(true), NtlmState::Last);
            assert_eq!(picked.get(true), Some(AuthMask::NTLM));
        }
    }

    #[test]
    fn absent_credentials_are_the_empty_string_and_not_an_error() {
        // `if(!userp) userp = ""; if(!passwdp) passwdp = "";` (`:170-174`).
        let type2 = fixture(FIXTURE_TYPE2_B64);
        let mut conn = NtlmConnection::new();
        quietly(|t| decode_type2_message(conn.data_mut(false), &type2, t))
            .expect("well formed");
        *conn.state_mut(false) = NtlmState::Type2;

        let credentials = Credentials::none();
        let clock = TestClock::default();
        let mut rng = FixedRng(0);
        let mut picked = AuthPickedInfo::new();

        let emission = quietly(|tracer| {
            let mut ctx = AuthContext {
                proxy: false,
                request_method: b"GET",
                request_target: b"/",
                clock: &clock,
                rng: &mut rng,
            };
            output_ntlm(&mut conn, &credentials, &mut picked, &mut ctx, tracer)
        })
        .expect("an empty identity still composes a message");

        // A message with no user and no domain: 64 + 24 + 24 + 11.
        let header = emission.header().expect("a header was emitted");
        assert!(header.starts_with("Authorization: NTLM "));
        assert!(header.ends_with("\r\n"));
        assert_eq!(conn.state(false), NtlmState::Type3);
    }

    #[test]
    fn a_full_three_message_exchange_runs_through_the_states() {
        // NONE -> (emit type-1) -> Type2 on input -> (emit type-3) -> Type3
        // -> Last on the next request, emitting nothing.
        let type2 = fixture(FIXTURE_TYPE2_B64);
        let encoded = base64::encode(&type2).expect("encodes");
        let mut conn = NtlmConnection::new();
        let mut picked = AuthPickedInfo::new();

        // Round 1: the server offers NTLM, we send a type-1 message.
        quietly(|t| input_ntlm(&mut conn, true, b"NTLM", t)).expect("offered");
        assert_eq!(conn.state(true), NtlmState::Type1);
        let (first, _) =
            emit(&mut conn, &mut picked, true, FIXTURE_USER, FIXTURE_PASSWORD);
        assert!(matches!(first, Ok(AuthEmission::Continuing(_))));

        // Round 2: the server challenges, we answer with a type-3 message.
        quietly(|t| {
            input_ntlm(&mut conn, true, format!("NTLM {encoded}").as_bytes(), t)
        })
        .expect("challenged");
        assert_eq!(conn.state(true), NtlmState::Type2);
        let (second, _) =
            emit(&mut conn, &mut picked, true, FIXTURE_USER, FIXTURE_PASSWORD);
        assert!(matches!(second, Ok(AuthEmission::Final(_))));
        assert_eq!(conn.state(true), NtlmState::Type3);

        // Round 3: authenticated. Nothing is emitted, and the mechanism is
        // recorded for `CURLINFO_PROXYAUTH_USED`.
        let (third, _) =
            emit(&mut conn, &mut picked, true, FIXTURE_USER, FIXTURE_PASSWORD);
        assert_eq!(third, Ok(AuthEmission::Nothing));
        assert_eq!(conn.state(true), NtlmState::Last);
        assert_eq!(picked.get(true), Some(AuthMask::NTLM));
    }

    #[test]
    fn the_emitted_header_matches_the_shared_emission_convention() {
        // `"%sAuthorization: NTLM %s\r\n"` (`lib/http_ntlm.c:207`, `:225`),
        // which `super::authorization_header` owns. Asserted here so that a
        // change to either cannot pass unnoticed.
        assert_eq!(
            authorization_header(true, "NTLM", "AAAA"),
            "Proxy-Authorization: NTLM AAAA\r\n"
        );
        assert_eq!(
            authorization_header(false, "NTLM", "AAAA"),
            "Authorization: NTLM AAAA\r\n"
        );
        assert_eq!(AuthScheme::Ntlm.header_scheme(), Some("NTLM"));
        assert_eq!(AuthScheme::Ntlm.label(), "NTLM");
        assert_eq!(header_prefix(true), "Proxy-");
        assert_eq!(header_prefix(false), "");
    }

    // -----------------------------------------------------------------------
    // The mechanism adapter.
    // -----------------------------------------------------------------------

    #[test]
    fn the_mechanism_drives_the_exchange_through_the_trait() {
        // The adapter must reach the same states and the same bytes as the
        // free functions, since it is dispatch and not behaviour.
        let type2 = fixture(FIXTURE_TYPE2_B64);
        let encoded = base64::encode(&type2).expect("encodes");
        let challenge = format!("NTLM {encoded}");

        let mut conn = NtlmConnection::new();
        let mut picked = AuthPickedInfo::new();
        let credentials =
            Credentials::new(Some(FIXTURE_USER), Some(FIXTURE_PASSWORD));
        let clock = TestClock::default();
        let mut rng = FixedRng(0xaa);

        let expected_b64: String = FIXTURE_TYPE3_B64
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();

        let config = TraceConfig::init().expect("trace config cannot fail");
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer =
            Tracer::new(&config, &mut sink).with_state(TraceState::verbose());

        // Scoped so that the borrows of `conn`, `rng` and `tracer` end before
        // the state is read back.
        {
            let mut mechanism = NtlmMechanism::new(
                &mut conn,
                &credentials,
                &mut picked,
                &mut tracer,
            );

            assert_eq!(mechanism.scheme(), AuthScheme::Ntlm);

            // `input` reaches `input_ntlm`.
            assert_eq!(mechanism.input(challenge.as_bytes(), true), Ok(()));

            // `output` reaches `output_ntlm` and produces the fixture's line.
            let mut ctx = AuthContext {
                proxy: true,
                request_method: b"GET",
                request_target: b"/",
                clock: &clock,
                rng: &mut rng,
            };
            assert_eq!(
                mechanism.output(&mut ctx),
                Ok(AuthEmission::Final(format!(
                    "Proxy-Authorization: NTLM {expected_b64}\r\n"
                )))
            );

            // The adapter's own formatter must not leak either, and it is
            // reachable only while the borrows are live.
            let rendered = format!("{mechanism:?}");
            assert!(rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");
        }

        assert_eq!(conn.state(true), NtlmState::Type3);
        assert_eq!(picked.get(true), None, "only the LAST arm records it");
    }

    #[test]
    fn the_mechanism_reports_the_diagnostics_the_trait_cannot_carry() {
        // The reason the tracer is a field: `HttpAuthMechanism::input` takes
        // none, and NTLM has five verbatim diagnostics that must still reach
        // `--verbose`.
        let mut conn = NtlmConnection::new();
        *conn.state_mut(false) = NtlmState::Type3;
        let mut picked = AuthPickedInfo::new();
        let credentials = Credentials::none();

        let config = TraceConfig::init().expect("trace config cannot fail");
        let mut sink = WriterSink::new(Vec::new());
        let result = {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());
            let mut mechanism = NtlmMechanism::new(
                &mut conn,
                &credentials,
                &mut picked,
                &mut tracer,
            );
            mechanism.input(b"NTLM", false)
        };

        assert_eq!(result, Err(CURLcode::RemoteAccessDenied));
        let log = String::from_utf8_lossy(&sink.into_inner()).into_owned();
        assert!(log.contains(HANDSHAKE_REJECTED), "{log}");
    }

    // -----------------------------------------------------------------------
    // Credentials must not reach any output this module controls.
    // -----------------------------------------------------------------------

    #[test]
    fn no_credential_or_hash_appears_in_trace_output() {
        // A full exchange with tracing at its most verbose, then a search of
        // everything the sink received for the password and for both hashes.
        //
        // This does NOT assert that curl redacts an `Authorization:` header --
        // it does not, and 168 fixtures compare that line byte for byte. It
        // asserts the narrower and binding property: no secret gains a path to
        // output that curl does not already have, and this module adds no
        // logging of its own.
        let password: &[u8] = b"correct horse battery staple";
        let type2 = fixture(FIXTURE_TYPE2_B64);
        let encoded = base64::encode(&type2).expect("encodes");

        let nt_hash = mk_nt_hash(password).expect("short password");
        let lm_hash = mk_lm_hash(password);
        let v2_hash =
            mk_ntlmv2_hash(b"alice", b"dom", &nt_hash).expect("short identity");

        let mut conn = NtlmConnection::new();
        let mut picked = AuthPickedInfo::new();
        let credentials = Credentials::new(Some(b"dom\\alice"), Some(password));
        let clock = TestClock::default();
        let mut rng = FixedRng(0x5a);

        let config = TraceConfig::init().expect("trace config cannot fail");
        let mut sink = WriterSink::new(Vec::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());

            // The whole exchange, plus the two structures' formatters, since a
            // `{:?}` of either is exactly how a secret escapes by accident.
            input_ntlm(&mut conn, false, b"NTLM", &mut tracer)
                .expect("offered");
            input_ntlm(
                &mut conn,
                false,
                format!("NTLM {encoded}").as_bytes(),
                &mut tracer,
            )
            .expect("challenged");

            let mut ctx = AuthContext {
                proxy: false,
                request_method: b"GET",
                request_target: b"/",
                clock: &clock,
                rng: &mut rng,
            };
            let emission = output_ntlm(
                &mut conn,
                &credentials,
                &mut picked,
                &mut ctx,
                &mut tracer,
            )
            .expect("composes");

            // Deliberately push every formatter's output through the sink.
            infof!(&mut tracer, "{:?}", conn);
            infof!(&mut tracer, "{:?}", nt_hash);
            infof!(&mut tracer, "{:?}", lm_hash);
            infof!(&mut tracer, "{:?}", credentials);
            infof!(
                &mut tracer,
                "{:?}",
                NtlmFlags::from_bits(FIXTURE_TYPE2_FLAGS)
            );
            infof!(&mut tracer, "{:?}", picked);

            // The emitted header is the one place credentials legitimately
            // appear, base64-encoded, exactly as curl emits it -- so it is
            // deliberately NOT written to the trace here.
            assert!(emission.header().is_some());
        }

        let log = sink.into_inner();

        // The password, in the clear.
        assert!(
            !contains_subslice(&log, password),
            "the password reached the trace log"
        );
        // The username IS printable -- curl prints it itself, in
        // `"%s auth using %s with user '%s'"` -- so it is not asserted absent.

        // Both hashes and the v2 hash, as raw bytes and as lowercase hex.
        for (name, secret) in [
            ("the NT hash", &nt_hash.0[..16]),
            ("the LM hash", &lm_hash.0[..16]),
            ("the NTLMv2 hash", &v2_hash[..]),
        ] {
            assert!(
                !contains_subslice(&log, secret),
                "{name} reached the trace log as bytes"
            );
            let hex: String =
                secret.iter().map(|byte| format!("{byte:02x}")).collect();
            assert!(
                !log.windows(hex.len()).any(|w| w == hex.as_bytes()),
                "{name} reached the trace log as hex"
            );
        }

        // The formatters really did run, so the search above is not vacuous.
        let text = String::from_utf8_lossy(&log);
        assert!(text.contains(REDACTED_PLACEHOLDER), "{text}");
        assert!(text.contains("NEGOTIATE_ALWAYS_SIGN"), "{text}");
    }

    /// Whether `haystack` contains `needle` as a contiguous run.
    ///
    /// A helper rather than an expression at each of four call sites, and
    /// deliberately not a string search: a secret is bytes, and a lossy
    /// conversion could hide one behind a replacement character.
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn the_key_formatters_print_a_placeholder_and_never_the_key() {
        let nt_hash = mk_nt_hash(b"Password").expect("short password");
        let rendered = format!("{nt_hash:?}");

        assert!(rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");
        // No byte of the key, in hex, appears -- checked against the published
        // vector so the assertion does not depend on the implementation.
        let hex: String = MSNLMP_NTOWFV1
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(!rendered.contains(&hex), "{rendered}");
        assert!(!rendered.contains("a4f4"), "{rendered}");
    }

    #[test]
    fn the_state_formatter_prints_the_block_length_and_not_the_block() {
        let secret_looking = vec![0xABu8; 64];
        let data = state_with(
            FIXTURE_TYPE2_FLAGS,
            FIXTURE_CHALLENGE,
            Some(secret_looking),
        );
        let rendered = format!("{data:?}");

        assert!(rendered.contains("target_info_len: 64"), "{rendered}");
        assert!(!rendered.contains("abab"), "{rendered}");

        // The flag word and the challenge ARE printed: both cross the wire in
        // clear text, and the C's own `DEBUG_ME` diagnostic prints them.
        assert!(rendered.contains("0x00018286"), "{rendered}");
        assert!(rendered.contains("0x739d406150e0c8d7"), "{rendered}");
        assert!(rendered.contains("NEGOTIATE_OEM"), "{rendered}");
    }

    // -----------------------------------------------------------------------
    // Cross-module invariants.
    // -----------------------------------------------------------------------

    #[test]
    fn ntlm_is_supported_unconditionally_and_its_state_is_per_connection() {
        // `Curl_auth_is_ntlm_supported()` returns TRUE unconditionally
        // (`lib/vauth/ntlm.c:315-318`), and `super` owns the predicate.
        assert!(is_ntlm_supported());

        // NTLM's state scope, which is what `NtlmConnection` implements.
        assert_eq!(state_scope(AuthScheme::Ntlm), Some(StateScope::Connection));
    }

    #[test]
    fn ntlm_sits_where_the_three_orderings_put_it() {
        // Asserted here as well as in `super` so that this module's own
        // position is checkable from the module that implements it.
        assert_eq!(PREFERENCE_ORDER[3], AuthScheme::Ntlm, "4th of 6");
        assert_eq!(EMISSION_ORDER[2], AuthScheme::Ntlm, "3rd");
        assert_eq!(CHALLENGE_ORDER[1], AuthScheme::Ntlm, "2nd");
        assert_eq!(AuthScheme::Ntlm.mask(), AuthMask::NTLM);

        // NTLM forces HTTP/1.1, which is why its state is per connection.
        assert_eq!(NTLM_FORCE_HTTP11, "Forcing HTTP/1.1 for NTLM");
        assert_eq!(NTLM_PROBLEM, "NTLM authentication problem, ignoring.");
    }

    #[test]
    fn every_diagnostic_is_the_c_string_verbatim() {
        // Five `infof`/`failf` strings, written out as literals. They reach
        // `--verbose` and `CURLOPT_ERRORBUFFER`, so their bytes are frozen.
        assert_eq!(AUTH_RESTARTED, "NTLM auth restarted");
        assert_eq!(HANDSHAKE_REJECTED, "NTLM handshake rejected");
        assert_eq!(
            HANDSHAKE_INTERNAL_ERROR,
            "NTLM handshake failure (internal error)"
        );
        assert_eq!(BAD_TYPE2, "NTLM handshake failure (bad type-2 message)");
        assert_eq!(
            BAD_TYPE2_TARGET_INFO,
            "NTLM handshake failure (bad type-2 message). Target Info Offset \
             Len is set incorrect by the peer"
        );
        assert_eq!(MESSAGE_TOO_BIG, "incoming NTLM message too big");
        assert_eq!(
            IDENTITY_TOO_BIG,
            "user + domain + hostname too big for NTLM"
        );

        // The specific target-info line begins with the general one, which is
        // why the C can emit both for one failure without reading oddly.
        assert!(BAD_TYPE2_TARGET_INFO.starts_with(BAD_TYPE2));

        // No diagnostic contains a newline: the emitter appends one, and
        // `infof!` refuses a format string that carries its own.
        for text in [
            AUTH_RESTARTED,
            HANDSHAKE_REJECTED,
            HANDSHAKE_INTERNAL_ERROR,
            BAD_TYPE2,
            BAD_TYPE2_TARGET_INFO,
            MESSAGE_TOO_BIG,
            IDENTITY_TOO_BIG,
        ] {
            assert!(!text.contains('\n'), "{text}");
            assert!(!text.contains('\r'), "{text}");
        }
    }

    #[test]
    fn the_hash_types_hold_three_seven_byte_keys() {
        let hash = HashKeys::zeroed();
        assert_eq!(hash.0.len(), HASH_KEY_LEN);
        assert_eq!(hash.0, [0u8; 21]);
        assert_eq!(hash.key(0), [0u8; 7]);
        assert_eq!(hash.key(2), [0u8; 7]);

        // `set_digest` writes the first sixteen and leaves the tail zero.
        let mut hash = HashKeys::zeroed();
        hash.set_digest(&MSNLMP_NTOWFV1);
        assert_eq!(&hash.0[..16], &MSNLMP_NTOWFV1);
        assert_eq!(&hash.0[16..], &[0u8; 5]);

        // The three windows tile the buffer without a gap or an overlap.
        assert_eq!(hash.key(0), hash.0[0..7]);
        assert_eq!(hash.key(1), hash.0[7..14]);
        assert_eq!(hash.key(2), hash.0[14..21]);
    }

    #[test]
    fn the_flag_newtype_is_a_set_and_not_an_integer() {
        let flags = NtlmFlags::from_bits(FIXTURE_TYPE2_FLAGS);
        assert_eq!(flags.bits(), FIXTURE_TYPE2_FLAGS);
        assert_eq!(NtlmFlags::NONE.bits(), 0);
        assert_eq!(NtlmFlags::default(), NtlmFlags::NONE);

        assert!(flags.contains(NTLMFLAG_NEGOTIATE_OEM));
        assert!(!flags.contains(NTLMFLAG_NEGOTIATE_NTLM2_KEY));

        // `contains` requires EVERY bit of the mask, which is the stronger of
        // the two readings and cannot silently accept a partial match.
        let both = NTLMFLAG_NEGOTIATE_OEM | NTLMFLAG_NEGOTIATE_UNICODE;
        assert!(!flags.contains(both), "only one of the two bits is set");
        assert!(NtlmFlags::from_bits(both).contains(both));

        // `without` is C's `&= ~x`, and clearing an absent bit is a no-op.
        assert_eq!(
            flags.without(NTLMFLAG_NEGOTIATE_OEM).bits(),
            FIXTURE_TYPE2_FLAGS & !NTLMFLAG_NEGOTIATE_OEM
        );
        assert_eq!(flags.without(NTLMFLAG_NEGOTIATE_UNICODE), flags);

        // The top bit survives, which a narrower type would have dropped.
        let top = NtlmFlags::from_bits(NTLMFLAG_NEGOTIATE_56);
        assert_eq!(top.bits(), 0x8000_0000);
        assert!(top.contains(NTLMFLAG_NEGOTIATE_56));
    }
}
