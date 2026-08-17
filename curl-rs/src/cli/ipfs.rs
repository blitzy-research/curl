// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Rewriting `ipfs://` and `ipns://` onto an IPFS gateway --
//! `src/tool_ipfs.c`.
//!
//! Two things happen here and nothing else: a gateway is *discovered*
//! (`ipfs_gateway`, `src/tool_ipfs.c:39-97`) and a URL is *rewritten*
//! against it (`ipfs_url_rewrite`, `:103-237`). The scheme itself is not
//! implemented, registered or transferred -- after the rewrite the URL is an
//! ordinary `http` or `https` URL and the rest of the tool cannot tell it
//! apart from one the user typed.
//!
//! # Everything observable here is frozen
//!
//! Small file, high test leverage: eighteen fixtures in the curl 8.x suite
//! exercise this code directly, every one of them byte-compared, so the three
//! error messages of `ipfs_url_rewrite` and its single path-composition
//! format string are not open to improvement. AAP section 0.8.2 states the
//! standard: *"a refactor that produces different-but-arguably-better output
//! has failed."*
//!
//! | Fixture | What it pins |
//! |---|---|
//! | `tests/data/test722` | IPFS with `--ipfs-gateway` |
//! | `tests/data/test723` | malformed argument gateway, error code 43 |
//! | `tests/data/test724` | gateway read from the gateway file |
//! | `tests/data/test725` | malformed gateway from the file, error code 3 |
//! | `tests/data/test726` | no gateway anywhere, error code 37 |
//! | `tests/data/test727` | IPNS |
//! | `tests/data/test730` | argument gateway carrying a path |
//! | `tests/data/test731` | gateway and path from the gateway file |
//! | `tests/data/test732` | input path preserved |
//! | `tests/data/test733` | input path and query preserved |
//! | `tests/data/test734` | input path, query, and a gateway path |
//! | `tests/data/test735` | IPNS with all three |
//! | `tests/data/test736` | `IPFS_PATH` without a trailing slash |
//! | `tests/data/test737` | `IPFS_PATH` with a trailing slash |
//! | `tests/data/test738` | `IPFS_PATH` set but no gateway file, code 37 |
//! | `tests/data/test739` | gateway carrying a query, error code 3 |
//! | `tests/data/test740` | multiline gateway file, first line only |
//! | `tests/data/test741` | first line is not a URL, error code 3 |
//!
//! The fixtures are immutable inputs (AAP section 0.8.1): a failure is a
//! defect here, never a reason to edit one. All eighteen point their gateway
//! at the plain HTTP test server, so they exercise this rewrite and then an
//! ordinary HTTP transfer.
//!
//! Note what `test741` actually pins, because the fixture and a natural
//! reading of the C part ways. Its gateway file begins `foo`, which is not
//! empty, so discovery *succeeds* and returns those three bytes; the failure
//! comes from the flags-`0` parse at `src/tool_ipfs.c:153` rejecting a URL
//! with no scheme. The fixture records error code **3**
//! (`CURLE_URL_MALFORMAT`), not 37. The empty-first-line case is a separate,
//! real path -- `:84-85` leaves the result null -- and it is covered by the
//! tests below rather than by a fixture.
//!
//! # `CURL_DISABLE_IPFS` is not a Cargo feature, so nothing here is gated
//!
//! C guards this whole translation unit with `#ifndef CURL_DISABLE_IPFS`
//! (`src/tool_ipfs.c:26` and `:238`), and guards its option row
//! (`src/tool_getparam.c:182-184`) and that row's handler (`:2424-2428`) the
//! same way. The workspace's feature vocabulary is fixed at fifteen names --
//! `http2`, `http3`, `ftp`, `ssh`, `websockets`, `cookies`, `hsts`, `altsvc`,
//! `doh`, `brotli`, `zstd` and `gzip` on by default, `negotiate`,
//! `hickory-dns` and `memdebug` off -- and `ipfs` is not one of them.
//! Inventing a sixteenth to stand in for the C macro would add a
//! configuration the specification does not describe, so this module is
//! **unconditional**, which is the default C build in which the macro is
//! undefined. No conditional-compilation attribute in this file tests a Cargo
//! feature at all, in any of its spellings, and
//! `source_gate::no_cargo_feature_gates_anything_here` keeps it that way.
//! `curl-rs/src/cli/libinfo.rs:227-231` reaches the same conclusion for the
//! two scheme tokens.
//!
//! # `ipfs` and `ipns` are tool-level tokens, and this module prints neither
//!
//! The `Protocols:` line of `--version` carries eleven tokens where the
//! engine knows only nine, and the two extra ones are these. Measured:
//!
//! 1. `lib/version.c`'s `supported_protocols[]` holds 33 names and contains
//!    neither `ipfs` nor `ipns`; the nine in core scope are `file`, `ftp`,
//!    `ftps`, `http`, `https`, `scp`, `sftp`, `ws` and `wss`.
//! 2. The two tokens are the *tool's*. `src/tool_libinfo.c:47-48` defines
//!    them as literals, separately from `built_in_protos`, and
//!    `src/tool_help.c:328-354` splices the literal `" ipfs ipns"` into the
//!    printed line at its alphabetical position.
//! 3. `tests/runtests.pl` never mentions `ipfs`. The harness feature arrives
//!    through `parseprotocols()` together with `tests/runtests.pl:841-844`,
//!    *"make each protocol an enabled 'feature'"*.
//! 4. Eighteen fixtures gate on `<features>ipfs</features>` -- the table
//!    above -- and every one of them is implementable, because the capability
//!    genuinely exists once this module does.
//!
//! Advertising them is therefore truthful rather than the over-reporting AAP
//! section 0.6.5 warns against; withholding them would be the safe-but-lossy
//! side of that asymmetry, skipping eighteen fixtures that pass. The correct
//! line is `file ftp ftps http https ipfs ipns scp sftp ws wss`.
//! `curl-rs/src/cli/help.rs` owns the printing and
//! `curl-rs/src/cli/libinfo.rs` owns the tokens; this module owns neither and
//! defines neither -- `ipfs_url_rewrite` receives the token its caller
//! matched.
//!
//! # What the caller owns
//!
//! `src/config2setopts.c:148-165` is the only call site. It compares the
//! parsed scheme against both tokens with `curl_strequal`, which folds ASCII
//! case, so `IPFS://` reaches here; on a match it assigns the token directly,
//! under the C comment *"short-circuit `proto_token`, we know it is ipfs or
//! ipns"*; and on any failure it sets `config->synthetic_error = TRUE`,
//! declared at `src/tool_cfgable.h:314` as *"if TRUE, this is tool-internal
//! error"* and read at `src/config2setopts.c:868` and
//! `src/tool_operate.c:596` to suppress the generic error report -- because
//! `helpf` has already spoken. **That flag belongs to the call site**, which
//! is `curl-rs/src/config/to_setopts.rs`; nothing here sets it, and
//! `ipfs_url_rewrite` takes its configuration by shared reference so that
//! it cannot.
//!
//! The `--ipfs-gateway` option itself belongs to `curl-rs/src/cli/args.rs`:
//! the row `{"ipfs-gateway", ARG_STRG, ' ', C_IPFS_GATEWAY}`
//! (`src/tool_getparam.c:183`, no short letter) and the `DENY_BLANK` handler
//! at `:2425-2427` that rejects an empty argument in the *parser*. By the
//! time a value reaches here it is non-empty by construction, and this module
//! adds, renames and re-defaults nothing (AAP sections 0.8.1 and 0.8.2).
//!
//! # The environment is a parameter, and it is read at run time
//!
//! `ipfs_gateway_with` takes the environment lookup and the file opener as
//! arguments; `ipfs_gateway` is the thin entry point that supplies both
//! from the live process. As in `curl-rs/src/config/findfile.rs`, this is
//! what lets the discovery chain be exercised without `std::env::set_var`,
//! which is process-global and would make tests race each other. No value is
//! captured at build time -- there is no `env!` or `option_env!` here -- so
//! nothing about the built binary depends on the machine that built it.
//!
//! # Three shapes that differ from the C, each because bytes matter
//!
//! 1. **URLs are bytes.** C's `char **url` is a byte string, and so is every
//!    URL in this crate: `GetOut::url` is `Option<Vec<u8>>`
//!    (`curl-rs/src/config/mod.rs:220`), `OperationConfig::ipfs_gateway` is
//!    `Option<Vec<u8>>` (`:493`), `crate::urlglob::UrlGlob::next_url` yields
//!    `Vec<u8>`, and `curl_rs_lib::url::Url` gets and sets `[u8]`. A `String`
//!    at this boundary would have to panic, lose bytes or fail on input C
//!    carries through, and all three are excluded.
//! 2. **The diagnostic sink is a parameter.** C's `helpf` writes to the
//!    file-scope `FILE *tool_stderr` (`src/tool_stderr.c:29`). This crate has
//!    no such global by design -- see the account on
//!    `crate::output::msgs::SinkHandle` -- so the sink is threaded down by
//!    reference exactly as `crate::cli::args` and `main` thread it.
//! 3. **The rewritten URL is stored only on success.** C frees `*url` at
//!    `src/tool_ipfs.c:197` *before* reading the new one at `:199`, so a
//!    failure in between would leave the caller holding null. That read can
//!    only fail with `CURLUE_NO_HOST` or `CURLUE_NO_SCHEME` -- both
//!    impossible once the scheme and host have just been set at `:179-181` --
//!    or on allocation failure, which Rust does not return. Composing first
//!    and assigning last is therefore observationally identical on every
//!    reachable path, and it removes a way for a failed rewrite to destroy
//!    the caller's URL.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::unix::ffi::OsStrExt;

use curl_rs_lib::error::{CURLUcode, CURLcode};
use curl_rs_lib::url::{SchemeRegistry, Url, UrlFlags, UrlPart};

use crate::config::OperationConfig;
use crate::output::msgs::{helpf, DiagnosticSink};

/// `MAX_GATEWAY_URL_LEN` -- `src/tool_ipfs.h:29`.
///
/// The `curlx_dyn_init` bound of `src/tool_ipfs.c:75`, and therefore a bound
/// on the *buffer*, not on the string. `dyn_nappend` computes
/// `fit = len + idx + 1` -- "new string + old string + zero byte" -- and
/// fails when `fit > toobig` (`lib/curlx/dynbuf.c:72` and `:82-85`). Appended
/// one byte at a time, as `:78-82` appends, the byte at index 9,999 is the
/// first to fail, so the longest first line this accepts is **9,999 bytes**.
/// [`GATEWAY_LINE_LIMIT`] carries that arithmetic rather than restating the
/// conclusion.
const MAX_GATEWAY_URL_LEN: usize = 10000;

/// The name whose value is used verbatim as the gateway --
/// `src/tool_ipfs.c:44`.
const IPFS_GATEWAY_ENV: &str = "IPFS_GATEWAY";

/// The name holding the IPFS data directory -- `src/tool_ipfs.c:50`.
const IPFS_PATH_ENV: &str = "IPFS_PATH";

/// The home directory the data directory defaults under --
/// `src/tool_ipfs.c:53`.
const HOME_ENV: &str = "HOME";

/// `"%s/.ipfs/"` minus its `%s` -- `src/tool_ipfs.c:56`.
///
/// Both slashes are the C's. The trailing one is what makes
/// [`has_trailing_slash`] answer `true` for a home-derived directory, so the
/// composed file name gains no second separator.
const IPFS_HOME_SUFFIX: &[u8] = b"/.ipfs/";

/// The file inside the data directory -- `src/tool_ipfs.c:62`.
const GATEWAY_FILE: &[u8] = b"gateway";

/// The separator inserted when the data directory does not end in one --
/// `src/tool_ipfs.c:63`, the false arm of its ternary.
const DIR_SEPARATOR: u8 = b'/';

/// `malformed target URL` -- `src/tool_ipfs.c:224`. Frozen.
const MSG_MALFORMED_URL: &str = "malformed target URL";

/// `IPFS automatic gateway detection failed` -- `src/tool_ipfs.c:227`.
/// Frozen.
const MSG_DETECTION_FAILED: &str = "IPFS automatic gateway detection failed";

/// `--ipfs-gateway was given a malformed URL` -- `src/tool_ipfs.c:230`.
/// Frozen.
///
/// The `--ipfs-gateway` in it is an option name, not the program name, so it
/// stays exactly as spelled. Nothing in this file reports the program's own
/// name; where C would, the name is `curl` (`src/tool_version.h:28`) and
/// `crate::output::msgs` owns the one copy of it.
const MSG_BAD_GATEWAY_ARGUMENT: &str =
    "--ipfs-gateway was given a malformed URL";

/// The longest first line [`ipfs_gateway_with`] accepts, in bytes.
///
/// Derived from [`MAX_GATEWAY_URL_LEN`] by the arithmetic documented there:
/// a one-byte append at index `idx` needs `idx + 2` bytes of buffer, so the
/// last index that fits is `MAX_GATEWAY_URL_LEN - 2` and the resulting length
/// is one more than that. `saturating_sub` rather than `-` so that no
/// arithmetic here can overflow, however the constant is ever changed.
const GATEWAY_LINE_LIMIT: usize = MAX_GATEWAY_URL_LEN.saturating_sub(1);

/// Whether `input` ends in a slash -- `has_trailing_slash`,
/// `src/tool_ipfs.c:32-37`.
///
/// ```c
/// size_t len = strlen(input);
/// return len && input[len - 1] == '/';
/// ```
///
/// A test on the last **byte**, and `false` for the empty string. Deliberately
/// not character-aware: C indexes bytes, and a UTF-8-boundary-respecting test
/// would answer differently for a value ending mid-sequence, which is a
/// change to which of the two arms of `:63` and `:189` is taken.
fn has_trailing_slash(input: &[u8]) -> bool {
    matches!(input.last(), Some(&byte) if byte == DIR_SEPARATOR)
}

/// The gateway discovery chain -- `ipfs_gateway`, `src/tool_ipfs.c:39-97`.
///
/// `getenv` answers an environment lookup and `open` opens the composed
/// gateway file, so both halves of the chain are observable from a test
/// without mutating the process. `open` receives the file name **exactly** as
/// `:61-63` composes it, which is what `tests/data/test736` and
/// `tests/data/test737` distinguish.
///
/// The chain, and the three *different* ways C reads the environment along
/// it -- the differences are observable and none of them is incidental:
///
/// 1. `getenv("IPFS_GATEWAY")` (`:44`) is a plain `getenv` and the test at
///    `:46` is on the **pointer only**, so a variable set to the empty string
///    is returned as an empty gateway. Nothing is validated here; the caller
///    parses it (`:132-157`).
/// 2. `curl_getenv("IPFS_PATH")` (`:50`) is not `getenv`: on the mandated
///    targets it is `return (env && env[0]) ? strdup(env) : NULL`
///    (`lib/getenv.c:66-67`), so an **empty** value counts as unset and falls
///    through to the home directory.
/// 3. `getenv("HOME")` (`:53`) is a plain `getenv` again, but `:55` tests
///    `home && *home`, so an empty home is rejected -- and with no data
///    directory to fall back to, `:57-58` fails outright.
///
/// Returns the first line of the gateway file, or [`None`] where C returns
/// `NULL`: no home to fall back to, an unopenable file, a first line over
/// [`GATEWAY_LINE_LIMIT`], or an empty first line.
fn ipfs_gateway_with<G, O, R>(getenv: G, open: O) -> Option<Vec<u8>>
where
    G: Fn(&'static str) -> Option<OsString>,
    O: FnOnce(&OsStr) -> Option<R>,
    R: Read,
{
    // `:44-47` -- "if(gateway_env) return curlx_strdup(gateway_env);". Bytes,
    // not a `String`: an environment value is arbitrary bytes on the mandated
    // targets, and a lossy conversion here would change the gateway the
    // caller then parses.
    if let Some(value) = getenv(IPFS_GATEWAY_ENV) {
        return Some(value.as_bytes().to_vec());
    }

    // `:50-59`. Step 2 above for the emptiness test, step 3 for the fallback.
    let ipfs_path: Vec<u8> = match getenv(IPFS_PATH_ENV) {
        Some(value) if !value.as_bytes().is_empty() => {
            value.as_bytes().to_vec()
        }
        // `:52-59` -- "fallback to \"~/.ipfs\", as that is the default
        // location". `:57-58` then fails when nothing was composed, which is
        // exactly the unset-or-empty home case.
        _ => match getenv(HOME_ENV) {
            Some(home) if !home.as_bytes().is_empty() => {
                let mut composed = home.as_bytes().to_vec();
                composed.extend_from_slice(IPFS_HOME_SUFFIX);
                composed
            }
            _ => return None,
        },
    };

    // `:61-63` -- `curl_maprintf("%s%sgateway", ipfs_path_c,
    //  has_trailing_slash(ipfs_path_c) ? "" : "/")`.
    //
    // Byte concatenation, and deliberately not the standard path joiner:
    // joining would normalise the separator and collapse the very distinction
    // the ternary draws, so `IPFS_PATH=/x/.ipfs` and `IPFS_PATH=/x/.ipfs/`
    // would stop being two different compositions and `tests/data/test736`
    // and `tests/data/test737` would stop testing anything.
    let mut file_name = ipfs_path;
    if !has_trailing_slash(&file_name) {
        file_name.push(DIR_SEPARATOR);
    }
    file_name.extend_from_slice(GATEWAY_FILE);

    // `:68` -- `curlx_fopen(gateway_composed_c, FOPEN_READTEXT)`, which is
    // plain `fopen` (`lib/curlx/fopen.h:81`) in mode `"r"` on every mandated
    // target (`lib/curl_setup.h:1258`). The `"rt"` spellings at `:1244` and
    // `:1254` are Windows and Cygwin only, so there is no text-mode
    // translation to emulate. `:71` and `:92-96`: an unopenable file is a
    // plain failure, not an error to report.
    let file = open(OsStr::from_bytes(&file_name))?;

    // `:72-82` -- "get the first line of the gateway file, ignore the rest":
    //
    //   while((c = getc(gfile)) != EOF && c != '\n' && c != '\r') { ... }
    //
    // Read one byte at a time through a buffered reader, which is what
    // `getc` on a `FILE *` is. A line reader would be wrong twice over: it
    // would not stop at a bare `\r`, and it would not let the length bound
    // below bite mid-line. Nothing is trimmed.
    let mut reader = BufReader::new(file);
    let mut collected: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            // `getc` returning EOF, and a read error reaches EOF too: C
            // cannot distinguish them and neither branch reports anything.
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let Some(&c) = byte.first() else { break };
        if c == b'\n' || c == b'\r' {
            break;
        }

        // `:80-81` -- `if(curlx_dyn_addn(&dyn, &c_char, 1)) goto fail;`. The
        // bound is the buffer's, so it bites one byte before the length
        // reaches `MAX_GATEWAY_URL_LEN`; see [`GATEWAY_LINE_LIMIT`]. C frees
        // the buffer and returns `NULL`, so an over-long line is discovery
        // failure rather than a truncated gateway.
        if collected.len() >= GATEWAY_LINE_LIMIT {
            return None;
        }
        collected.push(c);
    }

    // `:84-85` -- `if(curlx_dyn_len(&dyn)) gateway = curlx_dyn_ptr(&dyn);`,
    // and `gateway` stays `NULL` otherwise. An empty first line is therefore
    // discovery failure, which the caller reports as
    // `CURLE_FILE_COULDNT_READ_FILE`.
    if collected.is_empty() {
        None
    } else {
        Some(collected)
    }
}

/// [`ipfs_gateway_with`] against the live process.
///
/// `var_os` rather than `var`: `HOME` and `IPFS_PATH` are paths, and `var`
/// would reject a perfectly usable non-UTF-8 one, turning a discoverable
/// gateway into `CURLE_FILE_COULDNT_READ_FILE`. Read on every call and never
/// cached, so `--ipfs-gateway`'s documented fallbacks behave as
/// `docs/cmdline-opts/ipfs-gateway.md` describes them however the environment
/// changes.
fn ipfs_gateway() -> Option<Vec<u8>> {
    ipfs_gateway_with(std::env::var_os, |path| File::open(path).ok())
}

/// Rewrites `ipfs://<cid>` or `ipns://<cid>` onto an IPFS gateway --
/// `ipfs_url_rewrite`, `src/tool_ipfs.c:103-237`.
///
/// ```c
/// CURLcode ipfs_url_rewrite(CURLU *uh, const char *protocol, char **url,
///                           struct OperationConfig *config);
/// ```
///
/// `uh` is the already-parsed input URL, mutated in place as C mutates it.
/// `protocol` is the interned token the caller matched -- `proto_ipfs` or
/// `proto_ipns` from `crate::cli::libinfo`, never a literal restated here.
/// `url` receives the rewritten URL **only on success**; see translation
/// difference 3 in the module documentation. `config` is read for exactly one
/// field, [`OperationConfig::ipfs_gateway`], and is taken by shared reference
/// so that `synthetic_error` -- the call site's flag -- cannot be set from
/// here. `sink` is where the frozen diagnostics of [`report`] go; C reaches a
/// global instead, which is translation difference 2.
///
/// Returns `CURLE_OK`, or one of the three codes [`report`] documents. Every
/// one of them is emitted to `sink` before returning.
///
/// The scheme table comes from `curl_rs_lib::scheme_registry`, which is the
/// arrangement `curl-rs-lib/src/url/mod.rs:611-629` designates for exactly this
/// situation: `curl_url()` takes no arguments (`include/curl/urlapi.h:113`) and
/// reaches `Curl_get_scheme` directly, while `curl_rs_lib::url::Url::new`
/// requires the table as a constructor argument because the engine keeps no
/// global to reach for. The crate-root re-export is the sanctioned route to it
/// -- `protocols` itself is crate-private -- and there is no other way to
/// satisfy that signature from outside the engine.
#[allow(dead_code)] // The sole caller is `crate::config::to_setopts`, which
                    // `src/config2setopts.c:148-165` becomes and which is not
                    // yet part of this crate. The attribute is what keeps
                    // `cargo clippy -- -D warnings` honest in the meantime;
                    // it is not a licence to leave the function unexercised,
                    // and the tests below call it on every path.
pub(crate) fn ipfs_url_rewrite(
    sink: &mut dyn DiagnosticSink,
    uh: &mut Url,
    protocol: &str,
    url: &mut Vec<u8>,
    config: &OperationConfig,
) -> CURLcode {
    ipfs_url_rewrite_with(
        sink,
        uh,
        protocol,
        url,
        config,
        curl_rs_lib::scheme_registry(),
        ipfs_gateway,
    )
}

/// [`ipfs_url_rewrite`] with its two ambient dependencies made explicit.
///
/// `registry` is the scheme table the *gateway's* handle is built on -- C's
/// `curl_url()` at `src/tool_ipfs.c:118` reaches `Curl_get_scheme` directly,
/// which this workspace forbids, so the table is a constructor argument
/// (`curl_rs_lib::url::SchemeRegistry`). `discover` is the gateway discovery
/// chain, so a test can supply "no gateway" or a specific gateway file
/// without touching the process environment or the filesystem.
///
/// This is also where the structure that replaces C's `goto clean` lives.
/// [`compose`] does the work and returns either the rewritten URL or the code
/// to report; **its result is always mapped and then reported**, so there is
/// no path -- `?`, early `return` or otherwise -- that reaches the caller
/// without passing through [`report`]. C guarantees the same thing with a
/// single label that every failure jumps to, and losing that guarantee would
/// silently drop the stderr text six fixtures compare.
fn ipfs_url_rewrite_with<D>(
    sink: &mut dyn DiagnosticSink,
    uh: &mut Url,
    protocol: &str,
    url: &mut Vec<u8>,
    config: &OperationConfig,
    registry: &'static dyn SchemeRegistry,
    discover: D,
) -> CURLcode
where
    D: FnOnce() -> Option<Vec<u8>>,
{
    let result = match compose(uh, protocol, config, registry, discover) {
        // `:196-208` -- the rewritten URL replaces the caller's, and only
        // then is the result `CURLE_OK`.
        Ok(rewritten) => {
            *url = rewritten;
            CURLcode::Ok
        }
        Err(code) => code,
    };

    report(sink, result);
    result
}

/// The three frozen messages -- `src/tool_ipfs.c:221-235`.
///
/// C runs this block unconditionally after every free, so it is reached by
/// success and failure alike and emits nothing for success. The texts are
/// byte-exact and the mapping is exhaustive-by-default: any code other than
/// the three is silent, which is C's `default: break;` at `:232-233`.
///
/// | `result` | emitted |
/// |---|---|
/// | `CURLE_URL_MALFORMAT` | `malformed target URL` |
/// | `CURLE_FILE_COULDNT_READ_FILE` | `IPFS automatic gateway detection failed` |
/// | `CURLE_BAD_FUNCTION_ARGUMENT` | `--ipfs-gateway was given a malformed URL` |
/// | anything else, `CURLE_OK` included | nothing |
///
/// `helpf` is the right emitter and the only one: it is **ungated** --
/// neither `--silent` nor `--show-error` suppresses it
/// (`crate::output::msgs::helpf`, from `src/tool_msgs.c:107-123`) -- it
/// prefixes `curl: `, and it always follows the message with
/// `curl: try 'curl --help' or 'curl --manual' for more information`. None of
/// that is reproduced here; it is called.
///
/// Each message is passed as an *argument* rather than as the format string.
/// C hands the literal itself to `curl_mvfprintf` with nothing after it
/// (`src/tool_msgs.c:114`), so a `%` in the text would be interpreted; none of
/// the three contains one, and none contains a brace either, so both forms
/// emit identical bytes. Passing the text as data makes that true of any
/// message rather than of these three, and it keeps the constant's name
/// outside the literal where this module's own source audit can see it.
fn report(sink: &mut dyn DiagnosticSink, result: CURLcode) {
    match result {
        CURLcode::UrlMalformat => {
            helpf(sink, Some(format_args!("{}", MSG_MALFORMED_URL)));
        }
        CURLcode::FileCouldntReadFile => {
            helpf(sink, Some(format_args!("{}", MSG_DETECTION_FAILED)));
        }
        CURLcode::BadFunctionArgument => {
            helpf(sink, Some(format_args!("{}", MSG_BAD_GATEWAY_ARGUMENT)));
        }
        _ => {}
    }
}

/// Steps 2 to 12 of `src/tool_ipfs.c:118-206`, in the C's order.
///
/// Returns the rewritten URL, or the `CURLcode` [`report`] is to emit. The
/// default on every bail-out is `CURLE_URL_MALFORMAT`, which is what C
/// initialises `result` to at `:106` and what every plain `goto clean`
/// therefore returns; only the three branches that assign `result` first
/// depart from it, and no branch invents a fourth code.
///
/// `uh` is left partially rewritten on a late failure, exactly as C leaves
/// it: `:179-181` sets the scheme, host and port before `:188-194` can fail.
/// The sole call site discards the handle immediately afterwards
/// (`curl_url_cleanup` at `src/config2setopts.c:172`), so the partial state is
/// unobservable there -- but it is reproduced rather than tidied, because
/// tidying it would be a behaviour change made for tidiness.
fn compose<D>(
    uh: &mut Url,
    protocol: &str,
    config: &OperationConfig,
    registry: &'static dyn SchemeRegistry,
    discover: D,
) -> Result<Vec<u8>, CURLcode>
where
    D: FnOnce() -> Option<Vec<u8>>,
{
    // Step 2, `:118-123` -- `CURLU *gatewayurl = curl_url(); if(!gatewayurl)
    // { result = CURLE_FAILED_INIT; goto clean; }`.
    //
    // The failure branch is C's response to a failed `malloc`. Rust does not
    // return allocation failure -- the allocator aborts -- so there is no
    // condition to test and `CURLcode::FailedInit` is unreachable from this
    // function. The branch is documented rather than written, because writing
    // `if false` would be dead code and substituting any other code for it
    // would invent an error C never returns.
    let mut gatewayurl = Url::new(registry);

    // Step 3, `:125-127`. The CID is the input URL's **host**, URL-decoded.
    // C tests `getResult || !cid` and falls through to the default code; the
    // `CURLUcode` is discarded there, so it is discarded here.
    let cid = uh
        .get(UrlPart::Host, UrlFlags::URLDECODE)
        .map_err(|_| CURLcode::UrlMalformat)?;

    match &config.ipfs_gateway {
        // Step 4, `:129-145` -- the `--ipfs-gateway` argument, parsed with
        // `CURLU_GUESS_SCHEME` so that a gateway may omit its scheme. A parse
        // failure is the user's mistake in an option value, hence
        // `CURLE_BAD_FUNCTION_ARGUMENT` (`tests/data/test723`,
        // `tests/data/test739`).
        //
        // C additionally `strdup`s the argument at `:135` and treats a failed
        // duplication as `CURLE_URL_MALFORMAT` (`:136-139`). That copy is
        // never read: `gateway` is used only by the *other* branch's parse at
        // `:153`, and is otherwise just freed at `:211`. So the only
        // behaviour the copy carries is its own allocation failure, which
        // Rust does not report, and omitting it changes nothing observable.
        Some(argument) => {
            gatewayurl
                .set(UrlPart::Url, Some(argument), UrlFlags::GUESS_SCHEME)
                .map_err(|_| CURLcode::BadFunctionArgument)?;
        }

        // Step 5, `:146-157` -- discovery, then a parse with flags **`0`**.
        //
        // The asymmetry with step 4 is deliberate and observable: the
        // command-line gateway may omit its scheme, the file-supplied one may
        // not. `tests/data/test725` and `tests/data/test741` are the two
        // halves of the evidence -- the same malformed value that yields 43
        // from the argument yields 3 from the file. Merging the two parses
        // would collapse both fixtures.
        None => {
            let discovered = discover().ok_or(CURLcode::FileCouldntReadFile)?;
            gatewayurl
                .set(UrlPart::Url, Some(&discovered), UrlFlags::NONE)
                .map_err(|_| CURLcode::UrlMalformat)?;
        }
    }

    // Step 6, `:159-164` -- "check for unsupported gateway parts".
    //
    //   if(curl_url_get(gatewayurl, CURLUPART_QUERY, &gwquery, 0) !=
    //      CURLUE_NO_QUERY)
    //
    // Transcribed as the inequality C writes, not as "a query is present":
    // the test rejects **anything other than** "no query", so a successful
    // read fails it and so would any other error. The two are not the same
    // predicate, and only the inequality also rejects a gateway whose query
    // could not be read for some third reason. `tests/data/test739`.
    if gatewayurl.get(UrlPart::Query, UrlFlags::NONE) != Err(CURLUcode::NoQuery)
    {
        return Err(CURLcode::UrlMalformat);
    }

    // Step 7, `:166-171` -- the gateway's parts, in the C's evaluation order,
    // every one with `CURLU_URLDECODE`.
    //
    // The port read is load-bearing and easy to get wrong: without
    // `CURLU_DEFAULT_PORT` a gateway that states no port yields
    // `CURLUE_NO_PORT` (`lib/urlapi.c:1582-1584`), which C's `||` chain
    // treats as fatal. So `--ipfs-gateway http://host` is rejected with
    // `malformed target URL` while `http://host:80` is accepted. That is
    // curl 8.19.0-DEV's behaviour; all eighteen fixtures state a port. It is
    // preserved exactly, and neither flag nor fallback is added to soften it.
    let gwhost = uh_part(&gatewayurl, UrlPart::Host)?;
    let gwscheme = uh_part(&gatewayurl, UrlPart::Scheme)?;
    let gwport = uh_part(&gatewayurl, UrlPart::Port)?;
    let gwpath = uh_part(&gatewayurl, UrlPart::Path)?;

    // Step 8, `:173-176` -- "get the path from user input". C's comment reads
    // "inputpath might be NULL or a valid pointer now", and the code below
    // tolerates both. In practice the read cannot fail: `CURLUPART_PATH`
    // substitutes `"/"` when the handle holds none (`lib/urlapi.c:1603-1606`),
    // so the absent case arrives as a one-byte path and is handled by step 10
    // rather than by a null test.
    let inputpath = uh_part(uh, UrlPart::Path)?;

    // Step 9, `:178-182` -- "set gateway parts in input URL", every one with
    // `CURLU_URLENCODE`, in the C's order: scheme, then host, then port.
    uh.set(UrlPart::Scheme, Some(&gwscheme), UrlFlags::URLENCODE)
        .map_err(|_| CURLcode::UrlMalformat)?;
    uh.set(UrlPart::Host, Some(&gwhost), UrlFlags::URLENCODE)
        .map_err(|_| CURLcode::UrlMalformat)?;
    uh.set(UrlPart::Port, Some(&gwport), UrlFlags::URLENCODE)
        .map_err(|_| CURLcode::UrlMalformat)?;

    // Step 10, `:184-186` -- "if the input path is just a slash, clear it".
    //
    //   if(inputpath && (inputpath[0] == '/') && !inputpath[1])
    //     *inputpath = '\0';
    //
    // C truncates the buffer it was handed. Here the local is an owned value
    // and the empty case is a separate slice, so nothing is written through a
    // borrow of the handle's storage. Without this, `ipfs://<cid>` would
    // compose a path ending in a slash.
    let inputpath: &[u8] = if inputpath.as_slice() == b"/" {
        &[]
    } else {
        inputpath.as_slice()
    };

    // Step 11, `:188-194` -- the one format string the path composition is
    // frozen to:
    //
    //   curl_maprintf("%s%s%s/%s%s", gwpath,
    //                 has_trailing_slash(gwpath) ? "" : "/",
    //                 protocol, cid, inputpath ? inputpath : "");
    //
    // Read out: the gateway's path, then a separator **only** if that path
    // does not already end in one, then the protocol token, then a
    // **mandatory** separator, then the CID, then the input path or nothing.
    // `tests/data/test730` through `tests/data/test735` pin it between them.
    let mut pathbuffer = gwpath;
    if !has_trailing_slash(&pathbuffer) {
        pathbuffer.push(DIR_SEPARATOR);
    }
    pathbuffer.extend_from_slice(protocol.as_bytes());
    pathbuffer.push(DIR_SEPARATOR);
    pathbuffer.extend_from_slice(&cid);
    pathbuffer.extend_from_slice(inputpath);
    uh.set(UrlPart::Path, Some(&pathbuffer), UrlFlags::URLENCODE)
        .map_err(|_| CURLcode::UrlMalformat)?;

    // Step 12, `:199-206` -- the whole rewritten URL, with
    // `CURLU_URLENCODE`. The input's query and fragment were never touched,
    // so they reappear here; that is how `tests/data/test733`,
    // `tests/data/test734` and `tests/data/test735` keep their query strings.
    uh.get(UrlPart::Url, UrlFlags::URLENCODE)
        .map_err(|_| CURLcode::UrlMalformat)
}

/// One `curl_url_get(..., CURLU_URLDECODE)` whose failure is the default code.
///
/// Steps 7 and 8 perform five such reads and C treats every failure the same
/// way -- a bare `goto clean`, so `CURLE_URL_MALFORMAT`. Naming the pattern
/// once keeps the five call sites readable without hiding which flag is used
/// or letting a different code creep into one of them.
fn uh_part(url: &Url, what: UrlPart) -> Result<Vec<u8>, CURLcode> {
    url.get(what, UrlFlags::URLDECODE)
        .map_err(|_| CURLcode::UrlMalformat)
}

#[cfg(test)]
mod tests {
    use super::{
        has_trailing_slash, ipfs_gateway_with, ipfs_url_rewrite_with,
        GATEWAY_LINE_LIMIT, MAX_GATEWAY_URL_LEN, MSG_BAD_GATEWAY_ARGUMENT,
        MSG_DETECTION_FAILED, MSG_MALFORMED_URL,
    };
    use crate::cli::libinfo;
    use crate::config::OperationConfig;
    use crate::output::msgs::ERROR_PREFIX;
    use curl_rs_lib::error::{CURLUcode, CURLcode, Error};
    use curl_rs_lib::url::{
        SchemeInfo, SchemeRegistry, Url, UrlFlags, UrlPart,
    };
    use std::cell::RefCell;
    use std::ffi::{OsStr, OsString};
    use std::fmt;
    use std::os::unix::ffi::OsStrExt;

    /// Either failure a test here can meet, so that `?` may be used.
    ///
    /// The alternative is `unwrap` or `expect`, and this file admits neither
    /// -- not even in tests, where a panicking helper is exactly as capable of
    /// hiding a real outcome as one in the module proper. A test returns its
    /// failure instead, and the harness reports it through [`fmt::Debug`].
    enum TestFailure {
        /// A `CURLUcode` from building an input handle.
        Url(CURLUcode),
        /// A library error, from `crate::cli::libinfo::get_libcurl_info`.
        Lib(Error),
    }

    /// Written out rather than derived so that the payload is genuinely read.
    ///
    /// A `#[derive(Debug)]` is ignored by dead-code analysis, so the two
    /// fields would be reported as never read and the honest response is to
    /// use them rather than to silence the report. Both render through
    /// [`fmt::Display`], which the library implements for each code family
    /// (`curl-rs-lib/src/error.rs:489`) and for `Error` (`:1199`), so the
    /// harness prints the message rather than a discriminant name.
    impl fmt::Debug for TestFailure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Url(code) => write!(f, "URL API failure: {code}"),
                Self::Lib(error) => write!(f, "library failure: {error}"),
            }
        }
    }

    impl From<CURLUcode> for TestFailure {
        fn from(code: CURLUcode) -> Self {
            Self::Url(code)
        }
    }

    impl From<Error> for TestFailure {
        fn from(error: Error) -> Self {
            Self::Lib(error)
        }
    }

    /// `helpf`'s invariant second line -- `src/tool_msgs.c:118-122`.
    ///
    /// Spelled out rather than imported because
    /// `crate::output::msgs::HELP_TRY_TAIL` is private to that module. That is
    /// the right arrangement: this literal exists here to *assert* the frozen
    /// bytes independently, so a copy is the point rather than duplication.
    /// Note `curl`, never `curl-rs` -- `src/tool_version.h:28`.
    const TRY_LINE: &[u8] =
        b"curl: try 'curl --help' or 'curl --manual' for more information\n";

    /// A scheme table in which `http` and `https` are runnable.
    ///
    /// # Why the engine's own table will not do here
    ///
    /// `curl_rs_lib::scheme_registry()` knows all 33 schemes but currently
    /// answers `SchemeInfo::runnable == false` for every one of them, because
    /// its executor registry is empty in this checkout
    /// (`curl-rs-lib/src/protocols/mod.rs:233`). Step 9 of [`super::compose`]
    /// sets `CURLUPART_SCHEME`, and that setter requires a runnable scheme
    /// unless `CURLU_NON_SUPPORT_SCHEME` is passed -- which C does not pass
    /// (`src/tool_ipfs.c:179`, and `lib/urlapi.c:1646` for the requirement).
    /// So until an HTTP executor lands, the production path returns
    /// `CURLE_URL_MALFORMAT` for a reason that has nothing to do with this
    /// file, and the eighteen fixtures cannot pass.
    ///
    /// The fix is a protocol executor, not a flag here: adding
    /// `CURLU_NON_SUPPORT_SCHEME` would make this module accept gateway
    /// schemes curl rejects, which is precisely the behaviour change AAP
    /// section 0.8.1 forbids. So the registry is injected instead --
    /// `curl_rs_lib::url::Url::new` takes one by construction, which is the
    /// documented seam -- and the composition below is asserted against a
    /// table that says what curl's says.
    struct RunnableSchemes;

    impl SchemeRegistry for RunnableSchemes {
        fn lookup(&self, scheme: &[u8]) -> Option<SchemeInfo> {
            // ASCII folding, as `Curl_get_scheme` folds.
            if scheme.eq_ignore_ascii_case(b"http") {
                Some(SchemeInfo {
                    name: "http",
                    default_port: 80,
                    url_options: false,
                    runnable: true,
                })
            } else if scheme.eq_ignore_ascii_case(b"https") {
                Some(SchemeInfo {
                    name: "https",
                    default_port: 443,
                    url_options: false,
                    runnable: true,
                })
            } else {
                None
            }
        }
    }

    static RUNNABLE: RunnableSchemes = RunnableSchemes;

    /// The same table with `http` present but **not** runnable -- this
    /// checkout's engine, in miniature.
    ///
    /// Used to prove that step 9's failure is reported like any other, with
    /// `malformed target URL`, rather than escaping the report.
    struct UnrunnableSchemes;

    impl SchemeRegistry for UnrunnableSchemes {
        fn lookup(&self, scheme: &[u8]) -> Option<SchemeInfo> {
            if scheme.eq_ignore_ascii_case(b"http") {
                Some(SchemeInfo {
                    name: "http",
                    default_port: 80,
                    url_options: false,
                    runnable: false,
                })
            } else {
                None
            }
        }
    }

    static UNRUNNABLE: UnrunnableSchemes = UnrunnableSchemes;

    /// An environment lookup over explicit pairs; any other name is unset.
    ///
    /// Values are bytes so that a non-UTF-8 one can be supplied. Nothing here
    /// calls `std::env::set_var`, which is process-global and would make these
    /// tests race one another under the default threaded harness.
    fn lookup(
        pairs: &[(&'static str, &[u8])],
    ) -> impl Fn(&'static str) -> Option<OsString> {
        let owned: Vec<(&'static str, OsString)> = pairs
            .iter()
            .map(|(name, value)| {
                (*name, OsStr::from_bytes(value).to_os_string())
            })
            .collect();
        move |name| {
            owned
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        }
    }

    /// The bytes `helpf` writes for `message` -- prefix, message, newline,
    /// then the invariant try-line.
    fn expected_stderr(message: &str) -> Vec<u8> {
        let mut bytes = ERROR_PREFIX.as_bytes().to_vec();
        bytes.extend_from_slice(message.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(TRY_LINE);
        bytes
    }

    /// The input URL handle, parsed the way the call site parses it.
    ///
    /// `CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME`, exactly
    /// `src/config2setopts.c:143-144`. The second flag is what lets `ipfs://`
    /// parse at all: neither `ipfs` nor `ipns` is in curl's 33-scheme table.
    fn parse_input(
        registry: &'static dyn SchemeRegistry,
        url: &[u8],
    ) -> Result<Url, CURLUcode> {
        let mut handle = Url::new(registry);
        handle.set(
            UrlPart::Url,
            Some(url),
            UrlFlags::GUESS_SCHEME | UrlFlags::NON_SUPPORT_SCHEME,
        )?;
        Ok(handle)
    }

    /// What one rewrite produced: the code, the stderr bytes, and the URL.
    struct Outcome {
        code: CURLcode,
        stderr: Vec<u8>,
        url: Vec<u8>,
    }

    /// Drives one rewrite against the runnable table.
    ///
    /// `argument` is the `--ipfs-gateway` value, `discovered` is what the
    /// discovery chain yields when there is no argument, and `url` starts as
    /// the input so that "left untouched on failure" is observable.
    fn rewrite(
        argument: Option<&[u8]>,
        discovered: Option<&[u8]>,
        protocol: &str,
        input: &[u8],
    ) -> Result<Outcome, CURLUcode> {
        rewrite_with_registry(&RUNNABLE, argument, discovered, protocol, input)
    }

    /// [`rewrite`] with the scheme table chosen by the caller.
    fn rewrite_with_registry(
        registry: &'static dyn SchemeRegistry,
        argument: Option<&[u8]>,
        discovered: Option<&[u8]>,
        protocol: &str,
        input: &[u8],
    ) -> Result<Outcome, CURLUcode> {
        // Both handles share one table, as they do in production: the call
        // site builds the input handle from `curl_rs_lib::scheme_registry()`
        // and `src/tool_ipfs.c:118` builds the gateway's from the same C
        // table.
        let mut handle = parse_input(registry, input)?;
        let config = OperationConfig {
            ipfs_gateway: argument.map(<[u8]>::to_vec),
            ..OperationConfig::default()
        };
        let owned = discovered.map(<[u8]>::to_vec);
        let mut url = input.to_vec();
        let mut stderr: Vec<u8> = Vec::new();

        let code = ipfs_url_rewrite_with(
            &mut stderr,
            &mut handle,
            protocol,
            &mut url,
            &config,
            registry,
            || owned,
        );

        Ok(Outcome { code, stderr, url })
    }

    /// A rewrite whose input handle carries no host at all.
    ///
    /// The only way to exercise step 3's failure: an empty handle answers
    /// `CURLUE_NO_HOST` (`lib/urlapi.c:1575-1576`).
    fn rewrite_without_host(argument: &[u8]) -> Outcome {
        let mut handle = Url::new(&RUNNABLE);
        let config = OperationConfig {
            ipfs_gateway: Some(argument.to_vec()),
            ..OperationConfig::default()
        };
        let mut url = b"ipfs://".to_vec();
        let mut stderr: Vec<u8> = Vec::new();

        let code = ipfs_url_rewrite_with(
            &mut stderr,
            &mut handle,
            "ipfs",
            &mut url,
            &config,
            &RUNNABLE,
            || None,
        );

        Outcome { code, stderr, url }
    }

    /// The CID every fixture from `tests/data/test722` onward uses.
    const CID: &[u8] =
        b"bafybeidecnvkrygux6uoukouzps5ofkeevoqland7kopseiod6pzqvjg7u";

    /// `ipfs://<CID>` with `suffix` appended.
    fn ipfs_url(suffix: &[u8]) -> Vec<u8> {
        let mut url = b"ipfs://".to_vec();
        url.extend_from_slice(CID);
        url.extend_from_slice(suffix);
        url
    }

    // -- has_trailing_slash, src/tool_ipfs.c:32-37 -------------------------

    #[test]
    fn the_trailing_slash_test_is_on_the_last_byte() {
        // `return len && input[len - 1] == '/';` -- the length test first, so
        // the empty string is false rather than an out-of-bounds read.
        assert!(!has_trailing_slash(b""));
        assert!(has_trailing_slash(b"/"));
        assert!(!has_trailing_slash(b"a"));
        assert!(has_trailing_slash(b"a/"));
        assert!(has_trailing_slash(b"a//"));
        assert!(!has_trailing_slash(b"/a"));

        // Byte-wise, not character-wise: a value ending in a slash after a
        // multi-byte sequence is still a trailing slash, and one ending mid
        // sequence is still not. Written as bytes rather than as a non-ASCII
        // literal -- `scripts/spacecheck.pl` rejects non-ASCII source, and the
        // bytes are the whole point of the test anyway. `0xc3 0xa9` is U+00E9
        // encoded in UTF-8; `0xff 0xfe` is not valid UTF-8 at all, which a
        // char-boundary-aware test could not even inspect.
        assert!(has_trailing_slash(&[0xc3, 0xa9, b'/']));
        assert!(!has_trailing_slash(&[0xc3, 0xa9]));
        assert!(!has_trailing_slash(&[0xff, 0xfe]));
        assert!(has_trailing_slash(&[0xff, b'/']));
    }

    // -- the discovery chain, src/tool_ipfs.c:39-97 ------------------------

    #[test]
    fn an_ipfs_gateway_variable_short_circuits_the_rest_of_the_chain() {
        // `:44-47`. The names actually consulted are recorded, because "and
        // nothing else is read" is half of what this pins.
        let asked: RefCell<Vec<&'static str>> = RefCell::new(Vec::new());
        let inner = lookup(&[
            ("IPFS_GATEWAY", b"http://gw.example:8080"),
            ("IPFS_PATH", b"/should/not/be/read"),
            ("HOME", b"/should/not/be/read"),
        ]);
        let mut opened = false;

        let gateway = ipfs_gateway_with(
            |name| {
                asked.borrow_mut().push(name);
                inner(name)
            },
            |_| {
                opened = true;
                Some(&b""[..])
            },
        );

        assert_eq!(gateway, Some(b"http://gw.example:8080".to_vec()));
        assert_eq!(asked.into_inner(), vec!["IPFS_GATEWAY"]);
        assert!(
            !opened,
            "no gateway file is opened when the variable is set"
        );
    }

    #[test]
    fn an_empty_ipfs_gateway_variable_is_still_a_gateway() {
        // `:46` tests the pointer only, so `IPFS_GATEWAY=` yields an empty
        // gateway rather than falling through. Validation is the caller's:
        // the empty value then fails the parse at `:133`, which is
        // `CURLE_BAD_FUNCTION_ARGUMENT`.
        let gateway = ipfs_gateway_with(
            lookup(&[("IPFS_GATEWAY", b""), ("HOME", b"/home/user")]),
            |_| Some(&b"http://from.file:80"[..]),
        );

        assert_eq!(gateway, Some(Vec::new()));
    }

    #[test]
    fn an_ipfs_path_without_a_trailing_slash_gains_one() {
        // `tests/data/test736`: `IPFS_PATH=%LOGDIR/.ipfs`, no trailing slash,
        // so `:63` inserts the separator.
        let mut seen: Vec<u8> = Vec::new();

        let gateway = ipfs_gateway_with(
            lookup(&[("IPFS_PATH", b"/var/ipfs/.ipfs")]),
            |path| {
                seen = path.as_bytes().to_vec();
                Some(&b"http://from.file:80\n"[..])
            },
        );

        assert_eq!(seen, b"/var/ipfs/.ipfs/gateway".to_vec());
        assert_eq!(gateway, Some(b"http://from.file:80".to_vec()));
    }

    #[test]
    fn an_ipfs_path_with_a_trailing_slash_gains_nothing() {
        // `tests/data/test737`: the same directory spelled with the slash.
        // No doubled separator, which is the whole distinction the ternary at
        // `:63` draws and the reason the standard path joiner is not used.
        let mut seen: Vec<u8> = Vec::new();

        let gateway = ipfs_gateway_with(
            lookup(&[("IPFS_PATH", b"/var/ipfs/.ipfs/")]),
            |path| {
                seen = path.as_bytes().to_vec();
                Some(&b"http://from.file:80\n"[..])
            },
        );

        assert_eq!(seen, b"/var/ipfs/.ipfs/gateway".to_vec());
        assert_eq!(gateway, Some(b"http://from.file:80".to_vec()));
    }

    #[test]
    fn an_absent_ipfs_path_falls_back_to_the_home_directory() {
        // `:53-56`, `curl_maprintf("%s/.ipfs/", home)` -- note the trailing
        // slash in the format string, which is why the composed name has no
        // second separator. `tests/data/test724` relies on this.
        let mut seen: Vec<u8> = Vec::new();

        let gateway =
            ipfs_gateway_with(lookup(&[("HOME", b"/home/user")]), |path| {
                seen = path.as_bytes().to_vec();
                Some(&b"http://from.file:80\n"[..])
            });

        assert_eq!(seen, b"/home/user/.ipfs/gateway".to_vec());
        assert_eq!(gateway, Some(b"http://from.file:80".to_vec()));
    }

    #[test]
    fn an_empty_ipfs_path_is_treated_as_unset() {
        // `:50` is `curl_getenv`, not `getenv`, and on the mandated targets
        // that is `return (env && env[0]) ? strdup(env) : NULL`
        // (`lib/getenv.c:66-67`). So an empty value falls through to `HOME`
        // instead of composing `/gateway` at the filesystem root.
        let mut seen: Vec<u8> = Vec::new();

        let gateway = ipfs_gateway_with(
            lookup(&[("IPFS_PATH", b""), ("HOME", b"/home/user")]),
            |path| {
                seen = path.as_bytes().to_vec();
                Some(&b"http://from.file:80"[..])
            },
        );

        assert_eq!(seen, b"/home/user/.ipfs/gateway".to_vec());
        assert_eq!(gateway, Some(b"http://from.file:80".to_vec()));
    }

    #[test]
    fn an_absent_or_empty_home_fails_discovery() {
        // `:55` tests `home && *home`, and `:57-58` then fails because
        // nothing was composed. `tests/data/test726` is the fixture: a home
        // with no `.ipfs` directory, reported as
        // `CURLE_FILE_COULDNT_READ_FILE`.
        let mut opened = false;
        let unset = ipfs_gateway_with(lookup(&[]), |_| {
            opened = true;
            Some(&b"http://from.file:80"[..])
        });
        assert_eq!(unset, None);
        assert!(!opened, "no file is opened when there is no directory");

        let mut opened = false;
        let empty = ipfs_gateway_with(lookup(&[("HOME", b"")]), |_| {
            opened = true;
            Some(&b"http://from.file:80"[..])
        });
        assert_eq!(empty, None);
        assert!(!opened, "an empty HOME is rejected before any open");
    }

    #[test]
    fn an_unopenable_gateway_file_fails_discovery() {
        // `:71` and `:92-96`: `tests/data/test738` sets `IPFS_PATH` but writes
        // no gateway file, and expects error code 37.
        let gateway = ipfs_gateway_with(
            lookup(&[("IPFS_PATH", b"/var/ipfs/.ipfs/")]),
            |_| None::<&[u8]>,
        );

        assert_eq!(gateway, None);
    }

    #[test]
    fn only_the_first_line_of_the_gateway_file_is_read() {
        // `tests/data/test740`, a three-line file: "get the first line of the
        // gateway file, ignore the rest" (`:77`).
        let gateway =
            ipfs_gateway_with(lookup(&[("HOME", b"/home/user")]), |_| {
                Some(&b"http://from.file:80\nfoo\nbar\n"[..])
            });

        assert_eq!(gateway, Some(b"http://from.file:80".to_vec()));
    }

    #[test]
    fn the_first_line_ends_at_a_carriage_return() {
        // `:78` stops at `'\r'` as well as `'\n'`, so a CRLF file yields the
        // line without either byte. A reader that only recognised `'\n'`
        // would return a gateway with a trailing `\r` and the parse would
        // then fail.
        let crlf =
            ipfs_gateway_with(lookup(&[("HOME", b"/home/user")]), |_| {
                Some(&b"http://from.file:80\r\nfoo\r\n"[..])
            });
        assert_eq!(crlf, Some(b"http://from.file:80".to_vec()));

        // A bare `\r`, which no line reader would treat as a terminator.
        let bare =
            ipfs_gateway_with(lookup(&[("HOME", b"/home/user")]), |_| {
                Some(&b"http://from.file:80\rfoo"[..])
            });
        assert_eq!(bare, Some(b"http://from.file:80".to_vec()));
    }

    #[test]
    fn nothing_in_the_first_line_is_trimmed() {
        // `:78-82` copies every byte that is not a terminator, so leading and
        // trailing spaces survive into the gateway and make it malformed --
        // which is C's outcome, not a defect to correct here.
        let gateway =
            ipfs_gateway_with(lookup(&[("HOME", b"/home/user")]), |_| {
                Some(&b"  http://from.file:80  \n"[..])
            });

        assert_eq!(gateway, Some(b"  http://from.file:80  ".to_vec()));
    }

    #[test]
    fn an_empty_first_line_fails_discovery() {
        // `:84-85` -- `if(curlx_dyn_len(&dyn))`, so a file whose first line is
        // empty leaves the result null. Distinct from
        // `tests/data/test741`, whose first line is `foo`: that one discovers
        // three bytes and fails the flags-`0` parse instead.
        let leading_newline =
            ipfs_gateway_with(lookup(&[("HOME", b"/home/user")]), |_| {
                Some(&b"\nhttp://from.file:80\n"[..])
            });
        assert_eq!(leading_newline, None);

        let empty_file =
            ipfs_gateway_with(lookup(&[("HOME", b"/home/user")]), |_| {
                Some(&b""[..])
            });
        assert_eq!(empty_file, None);
    }

    #[test]
    fn the_first_line_is_bounded_by_the_dynbuf_cap() {
        // `:75` initialises the buffer with `MAX_GATEWAY_URL_LEN`, and
        // `dyn_nappend` fails when `len + idx + 1 > toobig`
        // (`lib/curlx/dynbuf.c:72`, `:82-85`). Appended one byte at a time,
        // that makes 9,999 the longest line that fits and the 10,000th byte
        // the first to fail -- at which point `:81` frees the buffer and
        // discovery fails rather than returning a truncated gateway.
        assert_eq!(MAX_GATEWAY_URL_LEN, 10000);
        assert_eq!(GATEWAY_LINE_LIMIT, 9999);

        let fits = vec![b'a'; GATEWAY_LINE_LIMIT];
        let accepted =
            ipfs_gateway_with(lookup(&[("HOME", b"/home/user")]), |_| {
                Some(&fits[..])
            });
        assert_eq!(accepted, Some(vec![b'a'; GATEWAY_LINE_LIMIT]));

        let one_too_many = vec![b'a'; GATEWAY_LINE_LIMIT + 1];
        let rejected =
            ipfs_gateway_with(lookup(&[("HOME", b"/home/user")]), |_| {
                Some(&one_too_many[..])
            });
        assert_eq!(rejected, None);

        // The bound applies mid-line, so a terminator beyond it does not
        // rescue the line.
        let mut long_line = vec![b'a'; MAX_GATEWAY_URL_LEN * 2];
        long_line.push(b'\n');
        let still_rejected =
            ipfs_gateway_with(lookup(&[("HOME", b"/home/user")]), |_| {
                Some(&long_line[..])
            });
        assert_eq!(still_rejected, None);
    }

    #[test]
    fn a_non_utf8_environment_value_is_carried_through() {
        // `HOME` and `IPFS_PATH` are paths and need not be UTF-8. `var_os`
        // keeps the bytes; `var` would reject them and turn a discoverable
        // gateway into `CURLE_FILE_COULDNT_READ_FILE`. Nothing here panics
        // and nothing is replaced with U+FFFD.
        let mut seen: Vec<u8> = Vec::new();
        let gateway = ipfs_gateway_with(
            lookup(&[("HOME", &[b'/', 0xff, 0xfe])]),
            |path| {
                seen = path.as_bytes().to_vec();
                Some(&b"http://from.file:80"[..])
            },
        );
        assert_eq!(
            seen,
            vec![
                b'/', 0xff, 0xfe, b'/', b'.', b'i', b'p', b'f', b's', b'/',
                b'g', b'a', b't', b'e', b'w', b'a', b'y'
            ]
        );
        assert_eq!(gateway, Some(b"http://from.file:80".to_vec()));

        // And a non-UTF-8 gateway value survives verbatim.
        let raw = ipfs_gateway_with(
            lookup(&[("IPFS_GATEWAY", &[0xff, 0xfe])]),
            |_| None::<&[u8]>,
        );
        assert_eq!(raw, Some(vec![0xff, 0xfe]));
    }

    // -- the rewrite: codes and the frozen messages -------------------------

    #[test]
    fn a_malformed_argument_gateway_is_a_bad_function_argument(
    ) -> Result<(), TestFailure> {
        // `tests/data/test723` -- an `--ipfs-gateway` of
        // `http://nonexisting,local:8080` expects error code 43. The comma is
        // not legal in a host name, so the `CURLU_GUESS_SCHEME` parse at `:133`
        // fails and `:142` assigns `CURLE_BAD_FUNCTION_ARGUMENT`.
        let outcome = rewrite(
            Some(b"http://nonexisting,local:8080"),
            None,
            "ipfs",
            &ipfs_url(b""),
        )?;

        assert_eq!(outcome.code, CURLcode::BadFunctionArgument);
        assert_eq!(outcome.stderr, expected_stderr(MSG_BAD_GATEWAY_ARGUMENT));

        // `tests/data/test739` reaches the same code through an IPNS URL with
        // a path and a query, which proves the argument is judged on its own.
        let ipns = rewrite(
            Some(b"http://nonexisting,local:8080"),
            None,
            "ipns",
            b"ipns://fancy.tld/a/b?foo=bar&aaa=bbb",
        )?;
        assert_eq!(ipns.code, CURLcode::BadFunctionArgument);
        assert_eq!(ipns.stderr, expected_stderr(MSG_BAD_GATEWAY_ARGUMENT));

        Ok(())
    }

    #[test]
    fn no_gateway_anywhere_is_a_failed_detection() -> Result<(), TestFailure> {
        // `tests/data/test726` and `tests/data/test738` both expect error
        // code 37: no argument, and discovery yields nothing.
        let outcome = rewrite(None, None, "ipfs", &ipfs_url(b""))?;

        assert_eq!(outcome.code, CURLcode::FileCouldntReadFile);
        assert_eq!(outcome.stderr, expected_stderr(MSG_DETECTION_FAILED));
        Ok(())
    }

    #[test]
    fn a_malformed_gateway_from_the_file_is_a_malformed_url(
    ) -> Result<(), TestFailure> {
        // `tests/data/test725` expects error code 3 for the *same* malformed
        // value that `tests/data/test723` reports as 43 from the argument.
        // That difference is the step-4/step-5 flag asymmetry, and it is the
        // reason the two parses must not be merged.
        let from_file = rewrite(
            None,
            Some(b"http://nonexisting,local:8080"),
            "ipfs",
            &ipfs_url(b""),
        )?;
        assert_eq!(from_file.code, CURLcode::UrlMalformat);
        assert_eq!(from_file.stderr, expected_stderr(MSG_MALFORMED_URL));

        // `tests/data/test741`: a first line that is not a URL. Discovery
        // succeeds -- `foo` is three non-empty bytes -- and the flags-`0`
        // parse rejects it for having no scheme, which is code 3 and not 37.
        let not_a_url = rewrite(None, Some(b"foo"), "ipfs", &ipfs_url(b""))?;
        assert_eq!(not_a_url.code, CURLcode::UrlMalformat);
        assert_eq!(not_a_url.stderr, expected_stderr(MSG_MALFORMED_URL));

        // The asymmetry, stated directly: a scheme-less gateway is accepted
        // from the argument, because `:133` guesses the scheme, and rejected
        // from the file, because `:153` does not.
        let guessed =
            rewrite(Some(b"gw.example:8080"), None, "ipfs", &ipfs_url(b""))?;
        assert_eq!(guessed.code, CURLcode::Ok);
        let unguessed =
            rewrite(None, Some(b"gw.example:8080"), "ipfs", &ipfs_url(b""))?;
        assert_eq!(unguessed.code, CURLcode::UrlMalformat);

        Ok(())
    }

    #[test]
    fn a_gateway_carrying_a_query_is_rejected() -> Result<(), TestFailure> {
        // `:159-164`, "check for unsupported gateway parts", and
        // `tests/data/test739`'s `--ipfs-gateway
        // "http://%HOSTIP:%HTTPPORT/some/path?biz=baz"`.
        let outcome = rewrite(
            Some(b"http://gw.example:8080/some/path?biz=baz"),
            None,
            "ipfs",
            &ipfs_url(b""),
        )?;

        assert_eq!(outcome.code, CURLcode::UrlMalformat);
        assert_eq!(outcome.stderr, expected_stderr(MSG_MALFORMED_URL));

        // The predicate is `!= CURLUE_NO_QUERY`, so a gateway with no query at
        // all is the only accepted shape.
        let no_query = rewrite(
            Some(b"http://gw.example:8080/some/path"),
            None,
            "ipfs",
            &ipfs_url(b""),
        )?;
        assert_eq!(no_query.code, CURLcode::Ok);

        Ok(())
    }

    #[test]
    fn a_gateway_without_a_port_is_rejected() -> Result<(), TestFailure> {
        // `:169` reads `CURLUPART_PORT` without `CURLU_DEFAULT_PORT`, so a
        // gateway that states no port answers `CURLUE_NO_PORT` and the `||`
        // chain treats it as fatal. Surprising, and preserved: every one of
        // the eighteen fixtures states a port, and softening this would be a
        // behaviour change made for taste.
        let outcome =
            rewrite(Some(b"http://gw.example"), None, "ipfs", &ipfs_url(b""))?;

        assert_eq!(outcome.code, CURLcode::UrlMalformat);
        assert_eq!(outcome.stderr, expected_stderr(MSG_MALFORMED_URL));
        Ok(())
    }

    #[test]
    fn success_emits_nothing() -> Result<(), TestFailure> {
        // `:232-233` -- `default: break;`. `CURLE_OK` reaches the switch like
        // every other code and produces no output at all, not even the
        // try-line.
        let outcome = rewrite(
            Some(b"http://gw.example:8080"),
            None,
            "ipfs",
            &ipfs_url(b""),
        )?;

        assert_eq!(outcome.code, CURLcode::Ok);
        assert_eq!(outcome.stderr, Vec::<u8>::new());
        Ok(())
    }

    #[test]
    fn every_message_is_emitted_once_with_the_prefix_and_the_try_line(
    ) -> Result<(), TestFailure> {
        // `helpf` writes `curl: `, the message, a newline, and then always
        // `curl: try 'curl --help' or 'curl --manual' for more information`
        // (`src/tool_msgs.c:113-122`). It consults no gate: `--silent` and
        // `--show-error` do not reach it, and its signature admits no
        // configuration to carry them, so there is nothing here that could
        // suppress it.
        let cases: [(Outcome, &str); 3] = [
            (
                rewrite(Some(b"http://a,b:1"), None, "ipfs", &ipfs_url(b""))?,
                MSG_BAD_GATEWAY_ARGUMENT,
            ),
            (
                rewrite(None, None, "ipfs", &ipfs_url(b""))?,
                MSG_DETECTION_FAILED,
            ),
            (
                rewrite(None, Some(b"foo"), "ipfs", &ipfs_url(b""))?,
                MSG_MALFORMED_URL,
            ),
        ];

        for (outcome, message) in &cases {
            assert_eq!(&outcome.stderr, &expected_stderr(message));

            // Exactly once: the message text appears a single time, and so
            // does the try-line.
            assert_eq!(
                outcome
                    .stderr
                    .windows(message.len())
                    .filter(|window| *window == message.as_bytes())
                    .count(),
                1
            );
            assert_eq!(
                outcome
                    .stderr
                    .windows(TRY_LINE.len())
                    .filter(|window| *window == TRY_LINE)
                    .count(),
                1
            );
            assert!(outcome.stderr.starts_with(ERROR_PREFIX.as_bytes()));
            assert!(outcome.stderr.ends_with(TRY_LINE));
        }

        // The three texts are distinct, so no case above could be passing by
        // matching another's message.
        assert_ne!(MSG_MALFORMED_URL, MSG_DETECTION_FAILED);
        assert_ne!(MSG_MALFORMED_URL, MSG_BAD_GATEWAY_ARGUMENT);
        assert_ne!(MSG_DETECTION_FAILED, MSG_BAD_GATEWAY_ARGUMENT);

        Ok(())
    }

    #[test]
    fn every_early_exit_reaches_the_report() -> Result<(), TestFailure> {
        // The enumeration C's single `clean:` label guarantees. Each row is a
        // distinct bail-out inside `compose`, named by its C line, with the
        // code it must produce and the text that must accompany it.
        //
        // Step 3, `:125-127` -- the host read, on a handle with no host.
        let no_host = rewrite_without_host(b"http://gw.example:8080");
        assert_eq!(no_host.code, CURLcode::UrlMalformat);
        assert_eq!(no_host.stderr, expected_stderr(MSG_MALFORMED_URL));

        // Step 4, `:141-144` -- the argument parse.
        let bad_argument =
            rewrite(Some(b"http://a,b:1"), None, "ipfs", &ipfs_url(b""))?;
        assert_eq!(bad_argument.code, CURLcode::BadFunctionArgument);
        assert!(!bad_argument.stderr.is_empty());

        // Step 5a, `:148-151` -- discovery found nothing.
        let no_gateway = rewrite(None, None, "ipfs", &ipfs_url(b""))?;
        assert_eq!(no_gateway.code, CURLcode::FileCouldntReadFile);
        assert!(!no_gateway.stderr.is_empty());

        // Step 5b, `:153-156` -- the flags-`0` parse.
        let unparsable = rewrite(None, Some(b"foo"), "ipfs", &ipfs_url(b""))?;
        assert_eq!(unparsable.code, CURLcode::UrlMalformat);
        assert!(!unparsable.stderr.is_empty());

        // Step 6, `:160-164` -- the query test.
        let with_query = rewrite(
            Some(b"http://gw.example:8080/p?q=1"),
            None,
            "ipfs",
            &ipfs_url(b""),
        )?;
        assert_eq!(with_query.code, CURLcode::UrlMalformat);
        assert!(!with_query.stderr.is_empty());

        // Step 7, `:167-171` -- a part read, here the absent port.
        let no_port =
            rewrite(Some(b"http://gw.example"), None, "ipfs", &ipfs_url(b""))?;
        assert_eq!(no_port.code, CURLcode::UrlMalformat);
        assert!(!no_port.stderr.is_empty());

        // Step 9, `:179-181` -- a part set. Reached with a scheme table in
        // which `http` parses but is not runnable, which is this checkout's
        // engine exactly; see [`RunnableSchemes`].
        let unrunnable = rewrite_with_registry(
            &UNRUNNABLE,
            Some(b"http://gw.example:8080"),
            None,
            "ipfs",
            &ipfs_url(b""),
        )?;
        assert_eq!(unrunnable.code, CURLcode::UrlMalformat);
        assert_eq!(unrunnable.stderr, expected_stderr(MSG_MALFORMED_URL));

        // Steps 11 and 12, `:188-206`, have no reachable failure once the
        // steps above have succeeded: the path is composed from bytes the
        // encoder accepts, and the URL read can only fail for a missing host
        // or scheme, both of which step 9 has just set. They are covered by
        // the structural gate below rather than by an input, because
        // manufacturing one would mean reaching past the public URL API.
        Ok(())
    }

    // -- the rewrite: path composition, src/tool_ipfs.c:188-194 -------------

    #[test]
    fn a_bare_gateway_composes_the_protocol_and_cid() -> Result<(), TestFailure>
    {
        // `tests/data/test722`: the gateway path is `/`, which already ends in
        // a slash, so no separator is inserted and the result has no doubled
        // one.
        let outcome = rewrite(
            Some(b"http://gw.example:8080"),
            None,
            "ipfs",
            &ipfs_url(b""),
        )?;

        assert_eq!(outcome.code, CURLcode::Ok);
        let mut expected = b"http://gw.example:8080/ipfs/".to_vec();
        expected.extend_from_slice(CID);
        assert_eq!(outcome.url, expected);
        Ok(())
    }

    #[test]
    fn a_gateway_path_without_a_trailing_slash_gains_one(
    ) -> Result<(), TestFailure> {
        // `tests/data/test730`: `--ipfs-gateway http://host:port/foo/bar`.
        let outcome = rewrite(
            Some(b"http://gw.example:8080/foo/bar"),
            None,
            "ipfs",
            &ipfs_url(b""),
        )?;

        assert_eq!(outcome.code, CURLcode::Ok);
        let mut expected = b"http://gw.example:8080/foo/bar/ipfs/".to_vec();
        expected.extend_from_slice(CID);
        assert_eq!(outcome.url, expected);
        Ok(())
    }

    #[test]
    fn a_gateway_path_with_a_trailing_slash_gains_nothing(
    ) -> Result<(), TestFailure> {
        // The other arm of the ternary at `:189`. `tests/data/test731` reads
        // its gateway and path from the file, so this drives the composition
        // through the real discovery chain -- newline and trailing lines
        // included -- rather than handing it a pre-cleaned value.
        let discovered =
            ipfs_gateway_with(lookup(&[("HOME", b"/home/user")]), |_| {
                Some(&b"http://gw.example:8080/foo/bar/\nignored\n"[..])
            });
        assert_eq!(
            discovered,
            Some(b"http://gw.example:8080/foo/bar/".to_vec())
        );

        let outcome =
            rewrite(None, discovered.as_deref(), "ipfs", &ipfs_url(b""))?;

        assert_eq!(outcome.code, CURLcode::Ok);
        let mut expected = b"http://gw.example:8080/foo/bar/ipfs/".to_vec();
        expected.extend_from_slice(CID);
        assert_eq!(outcome.url, expected);

        // Byte-for-byte identical to the un-slashed gateway above, and with
        // one separator rather than two: past the scheme's own `://` there is
        // no doubled slash anywhere in the result.
        let after_scheme = match outcome.url.get(b"http://".len()..) {
            Some(rest) => rest,
            None => &[],
        };
        assert!(!after_scheme.windows(2).any(|pair| pair == b"//"));
        Ok(())
    }

    #[test]
    fn the_input_path_is_preserved() -> Result<(), TestFailure> {
        // `tests/data/test732`: `ipfs://<cid>/a/b`.
        let outcome = rewrite(
            Some(b"http://gw.example:8080"),
            None,
            "ipfs",
            &ipfs_url(b"/a/b"),
        )?;

        assert_eq!(outcome.code, CURLcode::Ok);
        let mut expected = b"http://gw.example:8080/ipfs/".to_vec();
        expected.extend_from_slice(CID);
        expected.extend_from_slice(b"/a/b");
        assert_eq!(outcome.url, expected);
        Ok(())
    }

    #[test]
    fn an_input_path_of_one_slash_is_cleared() -> Result<(), TestFailure> {
        // `:184-186`. `CURLUPART_PATH` never reports absent -- it substitutes
        // `"/"` (`lib/urlapi.c:1603-1606`) -- so this is the branch that keeps
        // `ipfs://<cid>` and `ipfs://<cid>/` from composing a trailing slash.
        let bare = rewrite(
            Some(b"http://gw.example:8080"),
            None,
            "ipfs",
            &ipfs_url(b""),
        )?;
        let explicit = rewrite(
            Some(b"http://gw.example:8080"),
            None,
            "ipfs",
            &ipfs_url(b"/"),
        )?;

        let mut expected = b"http://gw.example:8080/ipfs/".to_vec();
        expected.extend_from_slice(CID);
        assert_eq!(bare.url, expected);
        assert_eq!(explicit.url, expected);
        assert!(!expected.ends_with(b"/"));

        // A two-byte path is not cleared: the C tests `!inputpath[1]`.
        let deeper = rewrite(
            Some(b"http://gw.example:8080"),
            None,
            "ipfs",
            &ipfs_url(b"/a"),
        )?;
        expected.extend_from_slice(b"/a");
        assert_eq!(deeper.url, expected);
        Ok(())
    }

    #[test]
    fn the_input_query_survives_the_rewrite() -> Result<(), TestFailure> {
        // `tests/data/test733`. Nothing touches `CURLUPART_QUERY` on the
        // input handle, so the query reappears when the whole URL is read
        // back at `:199`.
        let outcome = rewrite(
            Some(b"http://gw.example:8080"),
            None,
            "ipfs",
            &ipfs_url(b"/a/b?foo=bar&aaa=bbb"),
        )?;

        assert_eq!(outcome.code, CURLcode::Ok);
        let mut expected = b"http://gw.example:8080/ipfs/".to_vec();
        expected.extend_from_slice(CID);
        expected.extend_from_slice(b"/a/b?foo=bar&aaa=bbb");
        assert_eq!(outcome.url, expected);

        // `tests/data/test734`: the gateway carries a path as well.
        let with_gateway_path = rewrite(
            Some(b"http://gw.example:8080/some/path"),
            None,
            "ipfs",
            &ipfs_url(b"/a/b?foo=bar&aaa=bbb"),
        )?;
        let mut expected = b"http://gw.example:8080/some/path/ipfs/".to_vec();
        expected.extend_from_slice(CID);
        expected.extend_from_slice(b"/a/b?foo=bar&aaa=bbb");
        assert_eq!(with_gateway_path.url, expected);
        Ok(())
    }

    #[test]
    fn the_protocol_token_is_written_verbatim() -> Result<(), TestFailure> {
        // `:190` interpolates the caller's token, so `ipns` produces `/ipns/`.
        // The tokens come from `crate::cli::libinfo`, which owns them
        // (`src/tool_libinfo.c:47-48`); this module defines neither.
        let info = libinfo::get_libcurl_info()?;
        assert_eq!(info.proto_ipfs(), "ipfs");
        assert_eq!(info.proto_ipns(), "ipns");

        // `tests/data/test735`: IPNS with a path, a query, and a gateway path.
        let outcome = rewrite_with_registry(
            &RUNNABLE,
            Some(b"http://gw.example:8080/some/path"),
            None,
            info.proto_ipns(),
            b"ipns://fancy.tld/a/b?foo=bar&aaa=bbb",
        )?;

        assert_eq!(outcome.code, CURLcode::Ok);
        assert_eq!(
            outcome.url,
            b"http://gw.example:8080/some/path/ipns/fancy.tld/a/b\
              ?foo=bar&aaa=bbb"
                .to_vec()
        );

        // `tests/data/test727`: plain IPNS through the interned token.
        let plain = rewrite_with_registry(
            &RUNNABLE,
            Some(b"http://gw.example:8080"),
            None,
            info.proto_ipns(),
            &{
                let mut url = b"ipns://".to_vec();
                url.extend_from_slice(CID);
                url
            },
        )?;
        let mut expected = b"http://gw.example:8080/ipns/".to_vec();
        expected.extend_from_slice(CID);
        assert_eq!(plain.url, expected);
        Ok(())
    }

    #[test]
    fn an_upper_case_scheme_reaches_the_rewrite() -> Result<(), TestFailure> {
        // `src/config2setopts.c:150-151` compares with `curl_strequal`, which
        // folds ASCII case (`lib/strequal.c:76`), so `IPFS://` matches and the
        // *token* -- lower case -- is what this module receives and writes.
        // The composed path therefore says `ipfs` however the user spelled
        // the scheme.
        let info = libinfo::get_libcurl_info()?;
        assert!("IPFS".eq_ignore_ascii_case(info.proto_ipfs()));

        let outcome = rewrite_with_registry(
            &RUNNABLE,
            Some(b"http://gw.example:8080"),
            None,
            info.proto_ipfs(),
            b"IPFS://Example.CID",
        )?;

        assert_eq!(outcome.code, CURLcode::Ok);
        assert_eq!(
            outcome.url,
            b"http://gw.example:8080/ipfs/Example.CID".to_vec()
        );
        Ok(())
    }

    // -- structural properties ---------------------------------------------

    #[test]
    fn the_reported_codes_are_the_integers_the_fixtures_state(
    ) -> Result<(), TestFailure> {
        // The fixtures compare *numbers*, so the mapping from branch to
        // number is what they pin: `tests/data/test725` says 3,
        // `tests/data/test726` says 37 and `tests/data/test723` says 43.
        // These are the library's pinned discriminants, never literals in
        // this file.
        assert_eq!(CURLcode::Ok as i32, 0);
        assert_eq!(CURLcode::UrlMalformat as i32, 3);
        assert_eq!(CURLcode::FileCouldntReadFile as i32, 37);
        assert_eq!(CURLcode::BadFunctionArgument as i32, 43);

        assert_eq!(
            rewrite(None, Some(b"foo"), "ipfs", &ipfs_url(b""))?.code as i32,
            3
        );
        assert_eq!(
            rewrite(None, None, "ipfs", &ipfs_url(b""))?.code as i32,
            37
        );
        assert_eq!(
            rewrite(Some(b"http://a,b:1"), None, "ipfs", &ipfs_url(b""))?.code
                as i32,
            43
        );
        Ok(())
    }

    #[test]
    fn the_url_is_untouched_unless_the_rewrite_succeeds(
    ) -> Result<(), TestFailure> {
        let input = ipfs_url(b"/a/b");

        for outcome in [
            rewrite(Some(b"http://a,b:1"), None, "ipfs", &input)?,
            rewrite(None, None, "ipfs", &input)?,
            rewrite(None, Some(b"foo"), "ipfs", &input)?,
            rewrite(Some(b"http://gw.example"), None, "ipfs", &input)?,
        ] {
            assert_ne!(outcome.code, CURLcode::Ok);
            assert_eq!(outcome.url, input);
        }

        let ok =
            rewrite(Some(b"http://gw.example:8080"), None, "ipfs", &input)?;
        assert_eq!(ok.code, CURLcode::Ok);
        assert_ne!(ok.url, input);
        Ok(())
    }
}

/// Properties of this file that no input can demonstrate.
///
/// Four of them, and each is a rule about what the code does *not* contain, so
/// each is asserted against the source text the way
/// `curl-rs/src/cli/libinfo.rs:2109` and `curl-rs/src/main.rs:1819` assert
/// theirs. A behavioural test cannot see the absence of a thing.
///
/// Every check below is paired with a vacuity check, because a text gate that
/// matches nothing passes forever and says nothing.
#[cfg(test)]
mod source_gate {
    /// This file's own text; `include_str!` resolves relative to this file.
    const SOURCE: &str = include_str!("ipfs.rs");

    /// `line` with its `//` comment and every string literal removed.
    ///
    /// Literals collapse to a space so that stripping cannot fuse two adjacent
    /// tokens into one. Both forms of comment start with `//`, so `//!` and
    /// `///` are removed by the same split -- which is what makes it legitimate
    /// for the prose above to discuss the very tokens the gates forbid.
    fn code_only(line: &str) -> String {
        let without_comment = line.split("//").next().unwrap_or("");
        let mut out = String::with_capacity(without_comment.len());
        let mut in_string = false;
        let mut escaped = false;

        for ch in without_comment.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            if ch == '"' {
                in_string = true;
                out.push(' ');
                continue;
            }
            out.push(ch);
        }

        out
    }

    /// The whole file as code, comments and literals removed.
    ///
    /// Split on `'\n'` rather than with the obvious iterator, because this
    /// file's own audit forbids that method name outright -- it must not appear
    /// anywhere, or a gateway-file reader could use it and the audit would
    /// still pass. The two differ only on a trailing `\r`, which this file does
    /// not contain.
    fn code() -> String {
        strip(SOURCE)
    }

    /// The module proper as code: everything before the first test module.
    ///
    /// The "exactly once" checks below are about the shipped code, and the
    /// tests naturally name the same items many times over. Splitting at the
    /// first `#[cfg(test)]` keeps those counts meaningful.
    fn module_code() -> String {
        let head = match SOURCE.find("\n#[cfg(test)]") {
            Some(at) => SOURCE.get(..at).unwrap_or(SOURCE),
            None => SOURCE,
        };
        strip(head)
    }

    /// [`code_only`] over every line of `text`.
    fn strip(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for line in text.split('\n') {
            out.push_str(&code_only(line));
            out.push('\n');
        }
        out
    }

    #[test]
    fn no_cargo_feature_gates_anything_here() {
        // `CURL_DISABLE_IPFS` has no Cargo counterpart and must not acquire
        // one; see the module documentation. The token searched for is the
        // feature *test* rather than any one spelling of it, so the macro form,
        // the attribute form, its negation and its `all(...)` combination are
        // all caught by one rule -- and the attribute forms are the easy ones
        // to miss, because they do not read like a capability decision at all.
        assert!(
            !code().contains("feature ="),
            "no conditional compilation here may test a Cargo feature"
        );

        // Not vacuous: the prose really does discuss features, so the stripping
        // above is doing work rather than the file being silent on the subject.
        assert!(SOURCE.contains("feature"));
    }

    #[test]
    fn no_error_code_integer_is_written_in_this_file() {
        // Every code comes from `curl_rs_lib::error::CURLcode`, whose 103
        // discriminants are pinned there. A C enumerator name in *code* would
        // mean a value had been transcribed rather than referenced, so none
        // appears -- the variant paths are Rust names.
        let code = code();
        assert!(
            !code.contains("CURLE_"),
            "codes are referenced through CURLcode, never respelled"
        );
        assert!(
            !code.contains("CURLUE_"),
            "URL API codes are referenced through CURLUcode"
        );

        // Not vacuous: the comments cite the C enumerators throughout.
        assert!(SOURCE.contains("CURLE_URL_MALFORMAT"));
        assert!(SOURCE.contains("CURLUE_NO_QUERY"));
    }

    #[test]
    fn the_configuration_is_read_for_one_field_only() {
        // `src/tool_ipfs.c` reads exactly `config->ipfs_gateway` and writes
        // nothing. `synthetic_error` in particular belongs to the call site
        // (`src/config2setopts.c:160-161`), and the shared reference in the
        // signature is what makes that structural rather than a convention --
        // this check states the intent the signature enforces.
        let code = code();
        for (index, _) in code.match_indices("config.") {
            // `unwrap_or_default` rather than an index: a slice past the end of
            // the string is impossible here, and saying so with a fallible
            // accessor keeps this file free of any panicking path.
            let rest: &str =
                code.get(index + "config.".len()..).unwrap_or_default();
            assert!(
                rest.starts_with("ipfs_gateway"),
                "the only field read from the configuration is ipfs_gateway"
            );
        }

        // Not vacuous: the field really is read.
        assert!(code.contains("config.ipfs_gateway"));

        // And the flag is never named in code, in either spelling.
        assert!(!code.contains("synthetic_error"));
        assert!(SOURCE.contains("synthetic_error"));
    }

    #[test]
    fn none_of_the_forbidden_constructs_appears() {
        // The audit this file is held to, as one test rather than a shell
        // command someone has to remember to run. Each entry is forbidden for
        // its own reason:
        //
        // * the memory-safety keyword -- `curl-rs/src/main.rs:49` forbids it
        //   crate-wide, and this crate has no `mod ffi` to exempt.
        // * the four panicking accessors and the three panicking macros -- no
        //   panicking path anywhere, tests included, so a failure is always a
        //   value and never a backtrace with exit status 101.
        // * the three standard-stream printers -- diagnostics go through
        //   `crate::output::msgs`, which owns the frozen two-line shape.
        // * the path joiner -- it would normalise the separator and destroy the
        //   distinction `tests/data/test736` and `tests/data/test737` pin.
        // * the whole-file reader and the line iterator -- neither can honour
        //   the `\r`-or-`\n` stop or the length bound of the gateway-file read,
        //   so their absence is what keeps that loop honest.
        // * mutable global state, the C library's own bindings, and the build
        //   metadata macros -- no global, no raw route to the environment, and
        //   no self-reported identity taken from Cargo: the name this tool
        //   reports is `curl` (`src/tool_version.h:28`).
        //
        // Each token is spelled in two halves and rejoined at compile time, so
        // that this list does not itself contain any of the constructs it
        // forbids. The audit is also run as a plain `grep` over this file, and
        // a token written here in one piece would make that grep report a hit
        // and send every future reader chasing a false positive.
        let code = code();
        let forbidden: [&str; 18] = [
            concat!("un", "safe"),
            concat!("static", " mut"),
            concat!("unwrap", "()"),
            concat!("expect", "("),
            concat!("panic", "!"),
            concat!("todo", "!"),
            concat!("unimplemented", "!"),
            concat!("eprintln", "!"),
            concat!("println", "!"),
            concat!("print", "!"),
            concat!("libc", "::"),
            concat!("Path", "::join"),
            concat!("read_to", "_string"),
            concat!(".lines", "()"),
            concat!("CARGO", "_PKG_"),
            concat!("CARGO", "_BIN_"),
            concat!("env", "!("),
            concat!("option_env", "!("),
        ];

        for token in forbidden {
            assert!(
                !code.contains(token),
                "the forbidden construct {token} appears in code"
            );
        }

        // Not vacuous, in both directions. The stripping really does remove
        // comment text -- a phrase that appears only in the prose above is
        // absent from the stripped code -- and the stripped code is not empty,
        // so the loop is comparing against something.
        assert!(SOURCE.contains("goto clean"));
        assert!(!code.contains("goto clean"));
        assert!(code.contains("fn ipfs_url_rewrite"));
    }

    #[test]
    fn the_program_never_names_itself_curl_rs() {
        // The Cargo package and this file's path are spelled `curl-rs`; every
        // byte the tool emits says `curl`. The distinction matters because
        // `%VERSION` in a fixture expands to `curl/<version>` and the
        // diagnostics are compared literally.
        //
        // The path citations in the comments are exempt by construction: they
        // are comments, and `code_only` has already removed them. What is
        // checked is that no *string literal* in this file carries the crate
        // name -- so the literals are searched directly rather than stripped.
        for (index, _) in SOURCE.match_indices("curl-rs") {
            let line_start = match SOURCE.get(..index) {
                Some(head) => head.rfind('\n').map_or(0, |at| at + 1),
                None => 0,
            };
            let line_end = SOURCE
                .get(index..)
                .and_then(|tail| tail.find('\n'))
                .map_or(SOURCE.len(), |at| index + at);
            let line = SOURCE.get(line_start..line_end).unwrap_or("");
            assert!(
                code_only(line).is_empty()
                    || !code_only(line).contains("curl-rs"),
                "curl-rs may appear in comments only, not in code: {line}"
            );
        }

        // Not vacuous: the comments cite crate paths.
        assert!(SOURCE.contains("curl-rs/src/config/mod.rs"));
    }

    #[test]
    fn the_report_is_reached_from_exactly_one_place() {
        // C's `clean:` label is reached by every failure and by success alike.
        // Here that is one call, in one function, after the result is final --
        // so no `?` and no early `return` can bypass the frozen stderr text
        // that `tests/data/test723`, `test725`, `test726`, `test738`,
        // `test739` and `test741` compare.
        let code = module_code();
        assert_eq!(code.matches("report(sink, result)").count(), 1);
        assert_eq!(code.matches("fn report(").count(), 1);

        // And the three messages are each emitted from exactly one arm. Two
        // mentions apiece in the module proper: the constant's own definition
        // and the single `helpf` call that uses it.
        for token in [
            "MSG_MALFORMED_URL",
            "MSG_DETECTION_FAILED",
            "MSG_BAD_GATEWAY_ARGUMENT",
        ] {
            assert_eq!(
                code.matches(token).count(),
                2,
                "{token} must be defined once and emitted once"
            );
        }

        // `helpf` is the only emitter, and there are exactly three calls.
        assert_eq!(code.matches("helpf(sink").count(), 3);
    }

    #[test]
    fn no_diagnostic_gate_is_consulted() {
        // `helpf` is ungated: `src/tool_msgs.c:107-123` reads neither
        // `global->silent` nor `global->showerror`, and its Rust counterpart
        // takes no configuration at all. Naming either here would mean a gate
        // had been invented, so neither is named.
        let code = code();
        assert!(!code.contains("MsgConfig"));
        assert!(!code.contains("silent"));
        assert!(!code.contains("show_error"));

        // Not vacuous: the prose explains the absence.
        assert!(SOURCE.contains("silent"));
    }
}
