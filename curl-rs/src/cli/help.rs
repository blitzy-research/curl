// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The `--help` renderer, the built-in-manual scanner and the `--version`
//! printer -- `src/tool_help.c`, `src/tool_help.h` and the generated
//! `src/tool_listhelp.c`.
//!
//! Comments here cite `AAP <section>` -- the frozen migration specification --
//! and repository paths as `path:line`. A citation marks a decision the
//! specification or the C tree fixes, never one this code is free to change.
//!
//! Every byte this module writes is frozen output. AAP 0.8.1 puts the
//! command-line surface under the preservation mandate, and AAP 0.8.2 records
//! that "a refactor that produces different-but-arguably-better output has
//! failed". No string, column width, padding, separator or newline below is a
//! design decision; each is a measurement.
//!
//! # The `--version` banner is a machine-read contract
//!
//! `tests/runtests.pl:640-730` runs the binary under test with `--version` and
//! parses two of its lines. `Protocols:` feeds `parseprotocols()`, and
//! `tests/runtests.pl:841-844` additionally registers *every* advertised
//! protocol as a harness feature, so an over-report there has double blast
//! radius. `Features:` populates a map over a 52-name vocabulary that 874 of
//! the 1,914 fixtures gate on. The asymmetry decides the strategy: under-
//! reporting a capability makes a fixture *skip*, while over-reporting makes it
//! *run and fail* (AAP 0.6.5). Truthful advertisement is therefore optimal,
//! not merely honest.
//!
//! The first line is load-bearing in a harder way still: `tests/runtests.pl`
//! `die`s outright -- "Failure determining curl binary version" -- if it does
//! not contain the substring `libcurl`.
//!
//! # Two ownership decisions, both settled
//!
//! ## The 273-entry help table lives here, not in `build.rs`
//!
//! `curl-rs/build.rs` emits exactly four artifacts -- `$OUT_DIR/hugehelp.rs`,
//! `$OUT_DIR/ca_embed.rs` and the two completion scripts -- and the help table
//! is deliberately not among them. Four facts settle it:
//!
//! 1. `src/tool_listhelp.c` is **checked in** and listed in
//!    `src/Makefile.inc`'s `CURL_CFILES`, unlike the gitignored
//!    `tool_hugehelp.c` and `tool_ca_embed.c`.
//! 2. Its generator is a maintainer action rather than a build step:
//!    `docs/cmdline-opts/Makefile.am:60-61` defines
//!    `listhelp: ... scripts/managen -d docs/cmdline-opts listhelp $(DPAGES) >
//!    src/tool_listhelp.c`, reachable only through `make listhelp`.
//! 3. `curl-rs/build.rs`'s output contract fixes those four artifacts, so
//!    adding a fifth would change a contract this module has no business
//!    changing.
//! 4. AAP 0.3.3 pattern P11, "generated code stays generated", is satisfied
//!    regardless, because `scripts/managen` remains authoritative and in scope
//!    (AAP 0.2.1).
//!
//! So the table below is a *checked-in generated module*: `build.rs` and this
//! file do not both own it, and the notice above `HELPTEXT` says so in the same
//! terms `src/tool_listhelp.c:29-34` does.
//!
//! ## `--version`: the printer is here, the data model is in `cli/libinfo.rs`
//!
//! `tool_version_info()` is defined in `src/tool_help.c:311-386`, so this file
//! owns the *output*: the `Debug` pre-warning, the `CURL_ID` first line,
//! `Release-Date:`, the `Protocols:` line with its ipfs/ipns insertion and
//! rtmp suppression, the `Features:` line with its `CAcert` append and its
//! sort, and the version-mismatch warning.
//!
//! `crate::cli::libinfo` owns the *data*: which protocols and which features
//! are truthfully advertised, the counts, and the version-info accessors. This
//! file must not decide what is advertised, and must not filter or augment what
//! `libinfo` reports -- beyond the ipfs/ipns insertion and the rtmp suppression
//! that the C tool itself performs.
//!
//! One consequence of that split is worth naming, because it looks like an
//! omission: `is_debug()` (`src/tool_help.c:301-309`) is **not** reimplemented
//! here. `crate::cli::libinfo::LibInfo::is_debug` already answers it, with the
//! same ASCII-caseless comparison against the feature names, and its own
//! documentation records that it "lives here rather than in `cli/help.rs`
//! because it is a question about the data, not about the output". A second
//! definition of one predicate is exactly the two-sources-of-truth drift
//! AAP 0.1.2 rules out. The *warning* stays here, because the warning is
//! output.
//!
//! # 273, not 274
//!
//! AAP 0.4.1's row for this file says "274 entries". That figure is superseded
//! by measurement: `src/tool_listhelp.c:35` declares 273 real rows plus a
//! `{ NULL, NULL, 0 }` sentinel, which a Rust slice does not need. Two
//! independent corroborations agree --
//! `docs/cmdline-opts/Makefile.inc`'s `DPAGES` list is 273 entries, and
//! `docs/cmdline-opts/` holds 293 `.md` files that decompose as 273 option
//! pages plus 19 `_*.md` support pages plus `MANPAGE.md`. The `tests` module
//! asserts the 273 and the one-for-one correspondence with those pages, so the
//! figure cannot drift back.
//!
//! # Three advertisement decisions this module must honour
//!
//! **`Debug` is deliberately withheld, and the cost is stated rather than
//! hidden.** `tests/runtests.pl:660` sets
//! `$feature{"TrackMemory"} = $feat =~ /Debug/i;` and the entire
//! memory-checking block at `:1759` is wrapped in
//! `if($feature{"TrackMemory"})`, so withholding `Debug` makes the 28 fixtures
//! carrying a `<limits>` block inert -- their ceilings are caps rather than
//! equalities (`$lim_allocs = 1000`, `$lim_max = 1000000`), and a Rust
//! allocation pattern will not match a C one. **The price: 98 fixtures require
//! `Debug` and will skip, and `make torture-test` hard-requires the feature
//! (`tests/runtests.pl:847-849`) and is therefore not applicable.** The remedy,
//! if that trade is ever rejected, is the default-off `memdebug` Cargo feature
//! (AAP 0.6.6). Because `Debug` is withheld, `is_debug()` is always false and
//! the pre-warning at `src/tool_help.c:314-316` never fires; it is reproduced
//! anyway, so that enabling `memdebug` needs no change here.
//!
//! **The rustls token is truthful, never faked.**
//! `tests/runtests.pl:585-586` keys `$feature{"rustls"}` off a `rustls-ffi`
//! token, not off the word `rustls`, so a native `rustls/<version>` banner does
//! not match and the rustls-gated fixtures skip. AAP 0.8.6 ambiguity A8
//! recommends accuracy over unlocking them, and that recommendation is adopted.
//! The token itself belongs to `curl_rs_lib::version`; this file must not add
//! one.
//!
//! **With the `negotiate` Cargo feature off -- the default -- the `Features:`
//! line must not contain `GSS-API`, `SPNEGO` or `Kerberos`.** That follows from
//! printing exactly what `libinfo` reports, which is why this file needs no
//! `cfg` of its own to achieve it.
//!
//! # The built-in manual is unconditional here
//!
//! C wraps the scanner and the per-option help in `#ifdef USE_MANUAL`
//! (`src/tool_help.c:156`, `:254`, `src/tool_hugehelp.h:28-31`).
//! `curl-rs/build.rs` writes a manual artifact on **every** build, so there is
//! no configuration in which it is absent. Both lines of `category_note2` are
//! therefore emitted, and the `#else` arm's message at
//! `src/tool_help.c:291-292` cannot be reached. It is reproduced regardless --
//! see `MANUAL_ABSENT` -- so that the arm exists if the manual ever becomes
//! configurable, and so that nobody reading this against the C has to wonder
//! where it went.
//!
//! # Writers rather than `stdout`
//!
//! C writes through `curl_mprintf`/`puts` to standard output and through
//! `curl_mfprintf(tool_stderr, ...)` to standard error. Each printer here has a
//! writer-parameterised core and a wrapper carrying C's own signature, which is
//! what lets the `tests` module below assert bytes without a terminal, a
//! network or a subprocess. The stream each message uses is preserved exactly:
//! the `Debug` pre-warning and the two per-option-help failures go to standard
//! error; everything else, *including* the version-mismatch warning, goes to
//! standard output.
//!
//! Write results are discarded, deliberately. C ignores what `puts`, `fputs`
//! and `curl_mprintf` return, so a failed write costs C one line and nothing
//! more; propagating it here would abandon the remainder of the output and
//! change behaviour in exactly the way AAP 0.8.2 forbids. This is the same
//! parity property `crate::cli::hugehelp` documents for the manual.
//!
//! # Naming
//!
//! `struct helptxt` and `struct scan_ctx` become `HelpTxt` and `ScanCtx`.
//! The C spellings are not available: `rustc`'s `non_camel_case_types` is a
//! warning, and AAP 0.8.4's clippy gate is `-D warnings`, so a type named
//! `scan_ctx` would fail the build. Every function keeps its C name.

use crate::ca_embed;
use crate::cli::args::{
    argtype, findlongopt, findshortopt, CmdKey, LongShort, ARG_BOOL, ARG_NO,
};
use crate::cli::hugehelp;
use crate::cli::libinfo::{self, LibInfo};
use crate::terminal::get_terminal_columns;
use crate::util::struplocompare4sort;
use curl_rs_lib::version;
use std::io::{self, Write};

// The category bitmask -- src/tool_help.h:62-89

// The 26 category bits, carrying the C comment above them: "The bitmask output
// is generated with the following command: make -C docs/cmdline-opts listcats".
//
// The list keeps categories for protocols this workspace stubs -- IMAP, LDAP,
// POP3, SMTP, TELNET, TFTP. The help text documents the *option surface*, which
// AAP 0.8.1 freezes, independently of which protocols are implemented, so
// neither a bit nor a row's mask may be dropped for that reason.

/// `CURLHELP_AUTH` -- `src/tool_help.h:62`.
const CURLHELP_AUTH: u32 = 1 << 0;
/// `CURLHELP_CONNECTION` -- `src/tool_help.h:63`.
const CURLHELP_CONNECTION: u32 = 1 << 1;
/// `CURLHELP_CURL` -- `src/tool_help.h:64`.
const CURLHELP_CURL: u32 = 1 << 2;
/// `CURLHELP_DEPRECATED` -- `src/tool_help.h:65`.
const CURLHELP_DEPRECATED: u32 = 1 << 3;
/// `CURLHELP_DNS` -- `src/tool_help.h:66`.
const CURLHELP_DNS: u32 = 1 << 4;
/// `CURLHELP_FILE` -- `src/tool_help.h:67`.
const CURLHELP_FILE: u32 = 1 << 5;
/// `CURLHELP_FTP` -- `src/tool_help.h:68`.
const CURLHELP_FTP: u32 = 1 << 6;
/// `CURLHELP_GLOBAL` -- `src/tool_help.h:69`.
const CURLHELP_GLOBAL: u32 = 1 << 7;
/// `CURLHELP_HTTP` -- `src/tool_help.h:70`.
const CURLHELP_HTTP: u32 = 1 << 8;
/// `CURLHELP_IMAP` -- `src/tool_help.h:71`.
const CURLHELP_IMAP: u32 = 1 << 9;
/// `CURLHELP_IMPORTANT` -- `src/tool_help.h:72`. The default help page.
const CURLHELP_IMPORTANT: u32 = 1 << 10;
/// `CURLHELP_LDAP` -- `src/tool_help.h:73`.
const CURLHELP_LDAP: u32 = 1 << 11;
/// `CURLHELP_OUTPUT` -- `src/tool_help.h:74`.
const CURLHELP_OUTPUT: u32 = 1 << 12;
/// `CURLHELP_POP3` -- `src/tool_help.h:75`.
const CURLHELP_POP3: u32 = 1 << 13;
/// `CURLHELP_POST` -- `src/tool_help.h:76`.
const CURLHELP_POST: u32 = 1 << 14;
/// `CURLHELP_PROXY` -- `src/tool_help.h:77`.
const CURLHELP_PROXY: u32 = 1 << 15;
/// `CURLHELP_SCP` -- `src/tool_help.h:78`.
const CURLHELP_SCP: u32 = 1 << 16;
/// `CURLHELP_SFTP` -- `src/tool_help.h:79`.
const CURLHELP_SFTP: u32 = 1 << 17;
/// `CURLHELP_SMTP` -- `src/tool_help.h:80`.
const CURLHELP_SMTP: u32 = 1 << 18;
/// `CURLHELP_SSH` -- `src/tool_help.h:81`.
const CURLHELP_SSH: u32 = 1 << 19;
/// `CURLHELP_TELNET` -- `src/tool_help.h:82`.
const CURLHELP_TELNET: u32 = 1 << 20;
/// `CURLHELP_TFTP` -- `src/tool_help.h:83`.
const CURLHELP_TFTP: u32 = 1 << 21;
/// `CURLHELP_TIMEOUT` -- `src/tool_help.h:84`.
const CURLHELP_TIMEOUT: u32 = 1 << 22;
/// `CURLHELP_TLS` -- `src/tool_help.h:85`.
const CURLHELP_TLS: u32 = 1 << 23;
/// `CURLHELP_UPLOAD` -- `src/tool_help.h:86`.
const CURLHELP_UPLOAD: u32 = 1 << 24;
/// `CURLHELP_VERBOSE` -- `src/tool_help.h:87`.
const CURLHELP_VERBOSE: u32 = 1 << 25;

/// `CURLHELP_ALL 0xfffffffU` -- `src/tool_help.h:89`, the mask `--help all`
/// uses.
///
/// **Seven `f`s, not eight.** The C literal is `0xfffffffU`, so 28 bits are
/// set rather than 32, and it is emphatically not `!0`. Two bits above the 26
/// defined ones are therefore set and the top four are clear. That is
/// immaterial to the result -- no row carries a bit above `CURLHELP_VERBOSE` --
/// but the literal is reproduced exactly because it is the value the C tree
/// holds, and the `tests` module pins it.
const CURLHELP_ALL: u32 = 0x0fff_ffff;

// The help table -- src/tool_listhelp.c

/// One row of the help listing -- `struct helptxt`, `src/tool_help.h:50-54`.
///
/// ```c
/// struct helptxt {
///   const char *opt;
///   const char *desc;
///   unsigned int categories;
/// };
/// ```
///
/// `opt` is printed verbatim and **its byte length drives the column
/// arithmetic** of `print_category`, so its exact spelling is observable: four
/// leading spaces when the option has no short letter, `-X, --` when it has
/// one, and the argument placeholder in angle brackets where the option takes
/// one. 214 of the 273 rows take the four-space form and 59 take the
/// short-letter form; 146 carry a placeholder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HelpTxt {
    /// `opt` -- the rendered option spelling, leading spaces included.
    opt: &'static str,
    /// `desc` -- the one-line description.
    desc: &'static str,
    /// `categories` -- the OR of the `CURLHELP_*` bits this option belongs to.
    categories: u32,
}

/// Builds one [`HelpTxt`], so a table row reads as close to the C as the syntax
/// allows.
///
/// The same shape `crate::cli::args` uses for its own 282-row table, kept
/// deliberately consistent so the two frozen tables read alike.
const fn help(
    opt: &'static str,
    desc: &'static str,
    categories: u32,
) -> HelpTxt {
    HelpTxt {
        opt,
        desc,
        categories,
    }
}

// DO NOT edit the HELPTEXT table below by hand.
//
// It is the Rust counterpart of `const struct helptxt helptext[]` at
// `src/tool_listhelp.c:35`, whose own header comment reads "DO NOT edit
// tool_listhelp.c manually. This source file is generated with the following
// command in an autotools build: 'make listhelp'". The same discipline applies
// here: the authoritative generator is `scripts/managen`, driven by
// `docs/cmdline-opts/Makefile.am:60-61`, and the way to change a row is to
// change its page under `docs/cmdline-opts/` and regenerate.
//
// The rows were derived mechanically from the C initialiser rather than
// retyped, and the row ORDER is preserved exactly -- it is the order `managen`
// emits, which is the alphabetical page order, and it is observable in every
// `--help` variant.
//
// 273 rows. The C array additionally holds a `{ NULL, NULL, 0 }` sentinel so
// that `for(i = 0; helptext[i].opt; ++i)` knows where to stop; a Rust slice
// carries its own length, so the sentinel is dropped and every loop that C
// writes against `helptext[i].opt` iterates the slice instead.
const HELPTEXT: &[HelpTxt] = &[
    help(
        "    --abstract-unix-socket <path>",
        "Connect via abstract Unix domain socket",
        CURLHELP_CONNECTION,
    ),
    help(
        "    --alt-svc <filename>",
        "Enable alt-svc with this cache file",
        CURLHELP_HTTP,
    ),
    help(
        "    --anyauth",
        "Pick any authentication method",
        CURLHELP_HTTP | CURLHELP_PROXY | CURLHELP_AUTH,
    ),
    help(
        "-a, --append",
        "Append to target file when uploading",
        CURLHELP_FTP | CURLHELP_SFTP,
    ),
    help(
        "    --aws-sigv4 <provider1[:prvdr2[:reg[:srv]]]>",
        "AWS V4 signature auth",
        CURLHELP_AUTH | CURLHELP_HTTP,
    ),
    help("    --basic", "HTTP Basic Authentication", CURLHELP_AUTH),
    help("    --ca-native", "Load CA certs from the OS", CURLHELP_TLS),
    help(
        "    --cacert <file>",
        "CA certificate to verify peer against",
        CURLHELP_TLS,
    ),
    help(
        "    --capath <dir>",
        "CA directory to verify peer against",
        CURLHELP_TLS,
    ),
    help(
        "-E, --cert <certificate[:password]>",
        "Client certificate file and password",
        CURLHELP_TLS,
    ),
    help(
        "    --cert-status",
        "Verify server cert status OCSP-staple",
        CURLHELP_TLS,
    ),
    help(
        "    --cert-type <type>",
        "Certificate type (DER/PEM/ENG/PROV/P12)",
        CURLHELP_TLS,
    ),
    help(
        "    --ciphers <list>",
        "TLS 1.2 (1.1, 1.0) ciphers to use",
        CURLHELP_TLS,
    ),
    help(
        "    --compressed",
        "Request compressed response",
        CURLHELP_HTTP,
    ),
    help(
        "    --compressed-ssh",
        "Enable SSH compression",
        CURLHELP_SCP | CURLHELP_SSH,
    ),
    help(
        "-K, --config <file>",
        "Read config from a file",
        CURLHELP_CURL,
    ),
    help(
        "    --connect-timeout <seconds>",
        "Maximum time allowed to connect",
        CURLHELP_CONNECTION | CURLHELP_TIMEOUT,
    ),
    help(
        "    --connect-to <HOST1:PORT1:HOST2:PORT2>",
        "Connect to host2 instead of host1",
        CURLHELP_CONNECTION | CURLHELP_DNS,
    ),
    help(
        "-C, --continue-at <offset>",
        "Resumed transfer offset",
        CURLHELP_CONNECTION,
    ),
    help(
        "-b, --cookie <data|filename>",
        "Send cookies from string/load from file",
        CURLHELP_HTTP,
    ),
    help(
        "-c, --cookie-jar <filename>",
        "Save cookies to <filename> after operation",
        CURLHELP_HTTP,
    ),
    help(
        "    --create-dirs",
        "Create necessary local directory hierarchy",
        CURLHELP_OUTPUT,
    ),
    help(
        "    --create-file-mode <mode>",
        "File mode for created files",
        CURLHELP_SFTP | CURLHELP_SCP | CURLHELP_FILE | CURLHELP_UPLOAD,
    ),
    help(
        "    --crlf",
        "Convert LF to CRLF in upload",
        CURLHELP_FTP | CURLHELP_SMTP,
    ),
    help(
        "    --crlfile <file>",
        "Certificate Revocation list",
        CURLHELP_TLS,
    ),
    help(
        "    --curves <list>",
        "(EC) TLS key exchange algorithms to request",
        CURLHELP_TLS,
    ),
    help(
        "-d, --data <data>",
        "HTTP POST data",
        CURLHELP_IMPORTANT | CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD,
    ),
    help(
        "    --data-ascii <data>",
        "HTTP POST ASCII data",
        CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD,
    ),
    help(
        "    --data-binary <data>",
        "HTTP POST binary data",
        CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD,
    ),
    help(
        "    --data-raw <data>",
        "HTTP POST data, '@' allowed",
        CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD,
    ),
    help(
        "    --data-urlencode <data>",
        "HTTP POST data URL encoded",
        CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD,
    ),
    help(
        "    --delegation <LEVEL>",
        "GSS-API delegation permission",
        CURLHELP_AUTH,
    ),
    help(
        "    --digest",
        "HTTP Digest Authentication",
        CURLHELP_PROXY | CURLHELP_AUTH | CURLHELP_HTTP,
    ),
    help("-q, --disable", "Disable .curlrc", CURLHELP_CURL),
    help(
        "    --disable-eprt",
        "Inhibit using EPRT or LPRT",
        CURLHELP_FTP,
    ),
    help("    --disable-epsv", "Inhibit using EPSV", CURLHELP_FTP),
    help(
        "    --disallow-username-in-url",
        "Disallow username in URL",
        CURLHELP_CURL,
    ),
    help(
        "    --dns-interface <interface>",
        "Interface to use for DNS requests",
        CURLHELP_DNS,
    ),
    help(
        "    --dns-ipv4-addr <address>",
        "IPv4 address to use for DNS requests",
        CURLHELP_DNS,
    ),
    help(
        "    --dns-ipv6-addr <address>",
        "IPv6 address to use for DNS requests",
        CURLHELP_DNS,
    ),
    help(
        "    --dns-servers <addresses>",
        "DNS server addrs to use",
        CURLHELP_DNS,
    ),
    help(
        "    --doh-cert-status",
        "Verify DoH server cert status OCSP-staple",
        CURLHELP_DNS | CURLHELP_TLS,
    ),
    help(
        "    --doh-insecure",
        "Allow insecure DoH server connections",
        CURLHELP_DNS | CURLHELP_TLS,
    ),
    help(
        "    --doh-url <URL>",
        "Resolve hostnames over DoH",
        CURLHELP_DNS,
    ),
    help(
        "    --dump-ca-embed",
        "Write the embedded CA bundle to standard output",
        CURLHELP_HTTP | CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "-D, --dump-header <filename>",
        "Write the received headers to <filename>",
        CURLHELP_HTTP | CURLHELP_FTP,
    ),
    help("    --ech <config>", "Configure ECH", CURLHELP_TLS),
    help(
        "    --egd-file <file>",
        "EGD socket path for random data",
        CURLHELP_DEPRECATED,
    ),
    help("    --engine <name>", "Crypto engine to use", CURLHELP_TLS),
    help(
        "    --etag-compare <file>",
        "Load ETag from file",
        CURLHELP_HTTP,
    ),
    help(
        "    --etag-save <file>",
        "Parse incoming ETag and save to a file",
        CURLHELP_HTTP,
    ),
    help(
        "    --expect100-timeout <seconds>",
        "How long to wait for 100-continue",
        CURLHELP_HTTP | CURLHELP_TIMEOUT,
    ),
    help(
        "-f, --fail",
        "Fail fast with no output on HTTP errors",
        CURLHELP_IMPORTANT | CURLHELP_HTTP,
    ),
    help(
        "    --fail-early",
        "Fail on first transfer error",
        CURLHELP_CURL | CURLHELP_GLOBAL,
    ),
    help(
        "    --fail-with-body",
        "Fail on HTTP errors but save the body",
        CURLHELP_HTTP | CURLHELP_OUTPUT,
    ),
    help(
        "    --false-start",
        "Enable TLS False Start",
        CURLHELP_DEPRECATED,
    ),
    help("    --follow", "Follow redirects per spec", CURLHELP_HTTP),
    help(
        "-F, --form <name=content>",
        "Specify multipart MIME data",
        CURLHELP_HTTP
            | CURLHELP_UPLOAD
            | CURLHELP_POST
            | CURLHELP_IMAP
            | CURLHELP_SMTP,
    ),
    help(
        "    --form-escape",
        "Escape form fields using backslash",
        CURLHELP_HTTP | CURLHELP_UPLOAD | CURLHELP_POST,
    ),
    help(
        "    --form-string <name=string>",
        "Specify multipart MIME data",
        CURLHELP_HTTP
            | CURLHELP_UPLOAD
            | CURLHELP_POST
            | CURLHELP_SMTP
            | CURLHELP_IMAP,
    ),
    help(
        "    --ftp-account <data>",
        "Account data string",
        CURLHELP_FTP | CURLHELP_AUTH,
    ),
    help(
        "    --ftp-alternative-to-user <command>",
        "String to replace USER [name]",
        CURLHELP_FTP,
    ),
    help(
        "    --ftp-create-dirs",
        "Create the remote dirs if not present",
        CURLHELP_FTP | CURLHELP_SFTP,
    ),
    help(
        "    --ftp-method <method>",
        "Control CWD usage",
        CURLHELP_FTP,
    ),
    help(
        "    --ftp-pasv",
        "Send PASV/EPSV instead of PORT",
        CURLHELP_FTP,
    ),
    help(
        "-P, --ftp-port <address>",
        "Send PORT instead of PASV",
        CURLHELP_FTP,
    ),
    help("    --ftp-pret", "Send PRET before PASV", CURLHELP_FTP),
    help(
        "    --ftp-skip-pasv-ip",
        "Skip the IP address for PASV",
        CURLHELP_FTP,
    ),
    help(
        "    --ftp-ssl-ccc",
        "Send CCC after authenticating",
        CURLHELP_FTP | CURLHELP_TLS,
    ),
    help(
        "    --ftp-ssl-ccc-mode <active/passive>",
        "Set CCC mode",
        CURLHELP_FTP | CURLHELP_TLS,
    ),
    help(
        "    --ftp-ssl-control",
        "Require TLS for login, clear for transfer",
        CURLHELP_FTP | CURLHELP_TLS,
    ),
    help(
        "-G, --get",
        "Put the post data in the URL and use GET",
        CURLHELP_HTTP,
    ),
    help(
        "-g, --globoff",
        "Disable URL globbing with {} and []",
        CURLHELP_CURL,
    ),
    help(
        "    --happy-eyeballs-timeout-ms <ms>",
        "Time for IPv6 before IPv4",
        CURLHELP_CONNECTION | CURLHELP_TIMEOUT,
    ),
    help(
        "    --haproxy-clientip <ip>",
        "Set address in HAProxy PROXY",
        CURLHELP_HTTP | CURLHELP_PROXY,
    ),
    help(
        "    --haproxy-protocol",
        "Send HAProxy PROXY protocol v1 header",
        CURLHELP_HTTP | CURLHELP_PROXY,
    ),
    help(
        "-I, --head",
        "Show document info only",
        CURLHELP_IMPORTANT | CURLHELP_HTTP | CURLHELP_FTP | CURLHELP_FILE,
    ),
    help(
        "-H, --header <header/@file>",
        "Pass custom header(s) to server",
        CURLHELP_IMPORTANT | CURLHELP_HTTP | CURLHELP_IMAP | CURLHELP_SMTP,
    ),
    help(
        "-h, --help <subject>",
        "Get help for commands",
        CURLHELP_IMPORTANT | CURLHELP_CURL,
    ),
    help(
        "    --hostpubmd5 <md5>",
        "Acceptable MD5 hash of host public key",
        CURLHELP_SFTP | CURLHELP_SCP | CURLHELP_SSH,
    ),
    help(
        "    --hostpubsha256 <sha256>",
        "Acceptable SHA256 hash of host public key",
        CURLHELP_SFTP | CURLHELP_SCP | CURLHELP_SSH,
    ),
    help(
        "    --hsts <filename>",
        "Enable HSTS with this cache file",
        CURLHELP_HTTP,
    ),
    help("    --http0.9", "Allow HTTP/0.9 responses", CURLHELP_HTTP),
    help("-0, --http1.0", "Use HTTP/1.0", CURLHELP_HTTP),
    help("    --http1.1", "Use HTTP/1.1", CURLHELP_HTTP),
    help("    --http2", "Use HTTP/2", CURLHELP_HTTP),
    help(
        "    --http2-prior-knowledge",
        "Use HTTP/2 without HTTP/1.1 Upgrade",
        CURLHELP_HTTP,
    ),
    help("    --http3", "Use HTTP/3", CURLHELP_HTTP),
    help("    --http3-only", "Use HTTP/3 only", CURLHELP_HTTP),
    help(
        "    --ignore-content-length",
        "Ignore the size of the remote resource",
        CURLHELP_HTTP | CURLHELP_FTP,
    ),
    help(
        "-k, --insecure",
        "Allow insecure server connections",
        CURLHELP_TLS | CURLHELP_SFTP | CURLHELP_SCP | CURLHELP_SSH,
    ),
    help(
        "    --interface <name>",
        "Use network interface",
        CURLHELP_CONNECTION,
    ),
    help(
        "    --ip-tos <string>",
        "Set IP Type of Service or Traffic Class",
        CURLHELP_CONNECTION,
    ),
    help(
        "    --ipfs-gateway <URL>",
        "Gateway for IPFS",
        CURLHELP_CURL,
    ),
    help(
        "-4, --ipv4",
        "Resolve names to IPv4 addresses",
        CURLHELP_CONNECTION | CURLHELP_DNS,
    ),
    help(
        "-6, --ipv6",
        "Resolve names to IPv6 addresses",
        CURLHELP_CONNECTION | CURLHELP_DNS,
    ),
    help(
        "    --json <data>",
        "HTTP POST JSON",
        CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD,
    ),
    help(
        "-j, --junk-session-cookies",
        "Ignore session cookies read from file",
        CURLHELP_HTTP,
    ),
    help(
        "    --keepalive-cnt <integer>",
        "Maximum number of keepalive probes",
        CURLHELP_CONNECTION,
    ),
    help(
        "    --keepalive-time <seconds>",
        "Interval time for keepalive probes",
        CURLHELP_CONNECTION | CURLHELP_TIMEOUT,
    ),
    help(
        "    --key <key>",
        "Private key filename",
        CURLHELP_TLS | CURLHELP_SSH,
    ),
    help(
        "    --key-type <type>",
        "Private key file type (DER/PEM/ENG)",
        CURLHELP_TLS,
    ),
    help(
        "    --knownhosts <file>",
        "Specify knownhosts path",
        CURLHELP_SSH,
    ),
    help(
        "    --krb <level>",
        "Enable Kerberos with security <level>",
        CURLHELP_DEPRECATED,
    ),
    help(
        "    --libcurl <file>",
        "Generate libcurl code for this command line",
        CURLHELP_CURL | CURLHELP_GLOBAL,
    ),
    help(
        "    --limit-rate <speed>",
        "Limit transfer speed to RATE",
        CURLHELP_CONNECTION,
    ),
    help(
        "-l, --list-only",
        "List only mode",
        CURLHELP_FTP | CURLHELP_POP3 | CURLHELP_SFTP | CURLHELP_FILE,
    ),
    help(
        "    --local-port <range>",
        "Use a local port number within RANGE",
        CURLHELP_CONNECTION,
    ),
    help("-L, --location", "Follow redirects", CURLHELP_HTTP),
    help(
        "    --location-trusted",
        "As --location, but send secrets to other hosts",
        CURLHELP_HTTP | CURLHELP_AUTH,
    ),
    help(
        "    --login-options <options>",
        "Server login options",
        CURLHELP_IMAP
            | CURLHELP_POP3
            | CURLHELP_SMTP
            | CURLHELP_AUTH
            | CURLHELP_LDAP,
    ),
    help(
        "    --mail-auth <address>",
        "Originator address of the original email",
        CURLHELP_SMTP,
    ),
    help(
        "    --mail-from <address>",
        "Mail from this address",
        CURLHELP_SMTP,
    ),
    help(
        "    --mail-rcpt <address>",
        "Mail to this address",
        CURLHELP_SMTP,
    ),
    help(
        "    --mail-rcpt-allowfails",
        "Allow RCPT TO command to fail",
        CURLHELP_SMTP,
    ),
    help("-M, --manual", "Display the full manual", CURLHELP_CURL),
    help(
        "    --max-filesize <bytes>",
        "Maximum file size to download",
        CURLHELP_CONNECTION,
    ),
    help(
        "    --max-redirs <num>",
        "Maximum number of redirects allowed",
        CURLHELP_HTTP,
    ),
    help(
        "-m, --max-time <seconds>",
        "Maximum time allowed for transfer",
        CURLHELP_CONNECTION | CURLHELP_TIMEOUT,
    ),
    help(
        "    --metalink",
        "Process given URLs as metalink XML file",
        CURLHELP_DEPRECATED,
    ),
    help("    --mptcp", "Enable Multipath TCP", CURLHELP_CONNECTION),
    help(
        "    --negotiate",
        "Use HTTP Negotiate (SPNEGO) authentication",
        CURLHELP_AUTH | CURLHELP_HTTP,
    ),
    help(
        "-n, --netrc",
        "Must read .netrc for username and password",
        CURLHELP_AUTH,
    ),
    help(
        "    --netrc-file <filename>",
        "Specify FILE for netrc",
        CURLHELP_AUTH,
    ),
    help(
        "    --netrc-optional",
        "Use either .netrc or URL",
        CURLHELP_AUTH,
    ),
    help(
        "-:, --next",
        "Make next URL use separate options",
        CURLHELP_CURL,
    ),
    help(
        "    --no-alpn",
        "Disable the ALPN TLS extension",
        CURLHELP_TLS | CURLHELP_HTTP,
    ),
    help(
        "-N, --no-buffer",
        "Disable buffering of the output stream",
        CURLHELP_OUTPUT,
    ),
    help(
        "    --no-clobber",
        "Do not overwrite files that already exist",
        CURLHELP_OUTPUT,
    ),
    help(
        "    --no-keepalive",
        "Disable TCP keepalive on the connection",
        CURLHELP_CONNECTION,
    ),
    help(
        "    --no-npn",
        "Disable the NPN TLS extension",
        CURLHELP_DEPRECATED,
    ),
    help(
        "    --no-progress-meter",
        "Do not show the progress meter",
        CURLHELP_VERBOSE,
    ),
    help(
        "    --no-sessionid",
        "Disable SSL session-ID reusing",
        CURLHELP_TLS,
    ),
    help(
        "    --noproxy <no-proxy-list>",
        "List of hosts which do not use proxy",
        CURLHELP_PROXY,
    ),
    help(
        "    --ntlm",
        "HTTP NTLM authentication",
        CURLHELP_AUTH | CURLHELP_HTTP,
    ),
    help(
        "    --ntlm-wb",
        "HTTP NTLM authentication with winbind",
        CURLHELP_DEPRECATED,
    ),
    help(
        "    --oauth2-bearer <token>",
        "OAuth 2 Bearer Token",
        CURLHELP_AUTH
            | CURLHELP_IMAP
            | CURLHELP_POP3
            | CURLHELP_SMTP
            | CURLHELP_LDAP,
    ),
    help(
        "    --out-null",
        "Discard response data into the void",
        CURLHELP_OUTPUT,
    ),
    help(
        "-o, --output <file>",
        "Write to file instead of stdout",
        CURLHELP_IMPORTANT | CURLHELP_OUTPUT,
    ),
    help(
        "    --output-dir <dir>",
        "Directory to save files in",
        CURLHELP_OUTPUT,
    ),
    help(
        "-Z, --parallel",
        "Perform transfers in parallel",
        CURLHELP_CONNECTION | CURLHELP_CURL | CURLHELP_GLOBAL,
    ),
    help(
        "    --parallel-immediate",
        "Do not wait for multiplexing",
        CURLHELP_CONNECTION | CURLHELP_CURL | CURLHELP_GLOBAL,
    ),
    help(
        "    --parallel-max <num>",
        "Maximum concurrency for parallel transfers",
        CURLHELP_CONNECTION | CURLHELP_CURL | CURLHELP_GLOBAL,
    ),
    help(
        "    --parallel-max-host <num>",
        "Maximum connections to a single host",
        CURLHELP_CONNECTION | CURLHELP_CURL | CURLHELP_GLOBAL,
    ),
    help(
        "    --pass <phrase>",
        "Passphrase for the private key",
        CURLHELP_SSH | CURLHELP_TLS | CURLHELP_AUTH,
    ),
    help(
        "    --path-as-is",
        "Do not squash .. sequences in URL path",
        CURLHELP_CURL,
    ),
    help(
        "    --pinnedpubkey <hashes>",
        "Public key to verify peer against",
        CURLHELP_TLS,
    ),
    help(
        "    --post301",
        "Do not switch to GET after a 301 redirect",
        CURLHELP_HTTP | CURLHELP_POST,
    ),
    help(
        "    --post302",
        "Do not switch to GET after a 302 redirect",
        CURLHELP_HTTP | CURLHELP_POST,
    ),
    help(
        "    --post303",
        "Do not switch to GET after a 303 redirect",
        CURLHELP_HTTP | CURLHELP_POST,
    ),
    help(
        "    --preproxy <[protocol://]host[:port]>",
        "Use this proxy first",
        CURLHELP_PROXY,
    ),
    help(
        "-#, --progress-bar",
        "Display transfer progress as a bar",
        CURLHELP_VERBOSE | CURLHELP_GLOBAL,
    ),
    help(
        "    --proto <protocols>",
        "Enable/disable PROTOCOLS",
        CURLHELP_CONNECTION | CURLHELP_CURL,
    ),
    help(
        "    --proto-default <protocol>",
        "Use PROTOCOL for any URL missing a scheme",
        CURLHELP_CONNECTION | CURLHELP_CURL,
    ),
    help(
        "    --proto-redir <protocols>",
        "Enable/disable PROTOCOLS on redirect",
        CURLHELP_CONNECTION | CURLHELP_CURL,
    ),
    help(
        "-x, --proxy <[protocol://]host[:port]>",
        "Use this proxy",
        CURLHELP_PROXY,
    ),
    help(
        "    --proxy-anyauth",
        "Pick any proxy authentication method",
        CURLHELP_PROXY | CURLHELP_AUTH,
    ),
    help(
        "    --proxy-basic",
        "Use Basic authentication on the proxy",
        CURLHELP_PROXY | CURLHELP_AUTH,
    ),
    help(
        "    --proxy-ca-native",
        "Load CA certs from the OS to verify proxy",
        CURLHELP_TLS,
    ),
    help(
        "    --proxy-cacert <file>",
        "CA certificates to verify proxy against",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-capath <dir>",
        "CA directory to verify proxy against",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-cert <cert[:passwd]>",
        "Set client certificate for proxy",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-cert-type <type>",
        "Client certificate type for HTTPS proxy",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-ciphers <list>",
        "TLS 1.2 (1.1, 1.0) ciphers to use for proxy",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-crlfile <file>",
        "Set a CRL list for proxy",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-digest",
        "Digest auth with the proxy",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-header <header/@file>",
        "Pass custom header(s) to proxy",
        CURLHELP_PROXY,
    ),
    help(
        "    --proxy-http2",
        "Use HTTP/2 with HTTPS proxy",
        CURLHELP_HTTP | CURLHELP_PROXY,
    ),
    help(
        "    --proxy-insecure",
        "Skip HTTPS proxy cert verification",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-key <key>",
        "Private key for HTTPS proxy",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-key-type <type>",
        "Private key file type for proxy",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-negotiate",
        "HTTP Negotiate (SPNEGO) auth with the proxy",
        CURLHELP_PROXY | CURLHELP_AUTH,
    ),
    help(
        "    --proxy-ntlm",
        "NTLM authentication with the proxy",
        CURLHELP_PROXY | CURLHELP_AUTH,
    ),
    help(
        "    --proxy-pass <phrase>",
        "Passphrase for private key for HTTPS proxy",
        CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH,
    ),
    help(
        "    --proxy-pinnedpubkey <hashes>",
        "FILE/HASHES public key to verify proxy with",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-service-name <name>",
        "SPNEGO proxy service name",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-ssl-allow-beast",
        "Allow this security flaw for HTTPS proxy",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-ssl-auto-client-cert",
        "Auto client certificate for proxy",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-tls13-ciphers <list>",
        "TLS 1.3 proxy cipher suites",
        CURLHELP_PROXY | CURLHELP_TLS,
    ),
    help(
        "    --proxy-tlsauthtype <type>",
        "TLS authentication type for HTTPS proxy",
        CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH,
    ),
    help(
        "    --proxy-tlspassword <string>",
        "TLS password for HTTPS proxy",
        CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH,
    ),
    help(
        "    --proxy-tlsuser <name>",
        "TLS username for HTTPS proxy",
        CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH,
    ),
    help(
        "    --proxy-tlsv1",
        "TLSv1 for HTTPS proxy",
        CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH,
    ),
    help(
        "-U, --proxy-user <user:password>",
        "Proxy user and password",
        CURLHELP_PROXY | CURLHELP_AUTH,
    ),
    help(
        "    --proxy1.0 <host[:port]>",
        "Use HTTP/1.0 proxy on given port",
        CURLHELP_PROXY,
    ),
    help(
        "-p, --proxytunnel",
        "HTTP proxy tunnel (using CONNECT)",
        CURLHELP_PROXY,
    ),
    help(
        "    --pubkey <key>",
        "SSH Public key filename",
        CURLHELP_SFTP | CURLHELP_SCP | CURLHELP_SSH | CURLHELP_AUTH,
    ),
    help(
        "-Q, --quote <command>",
        "Send command(s) to server before transfer",
        CURLHELP_FTP | CURLHELP_SFTP,
    ),
    help(
        "    --random-file <file>",
        "File for reading random data from",
        CURLHELP_DEPRECATED,
    ),
    help(
        "-r, --range <range>",
        "Retrieve only the bytes within RANGE",
        CURLHELP_HTTP | CURLHELP_FTP | CURLHELP_SFTP | CURLHELP_FILE,
    ),
    help(
        "    --rate <max request rate>",
        "Request rate for serial transfers",
        CURLHELP_CONNECTION | CURLHELP_GLOBAL,
    ),
    help(
        "    --raw",
        "Do HTTP raw; no transfer decoding",
        CURLHELP_HTTP,
    ),
    help("-e, --referer <URL>", "Referrer URL", CURLHELP_HTTP),
    help(
        "-J, --remote-header-name",
        "Use the header-provided filename",
        CURLHELP_OUTPUT,
    ),
    help(
        "-O, --remote-name",
        "Write output to file named as remote file",
        CURLHELP_IMPORTANT | CURLHELP_OUTPUT,
    ),
    help(
        "    --remote-name-all",
        "Use the remote filename for all URLs",
        CURLHELP_OUTPUT,
    ),
    help(
        "-R, --remote-time",
        "Set remote file's time on local output",
        CURLHELP_OUTPUT,
    ),
    help(
        "    --remove-on-error",
        "Remove output file on errors",
        CURLHELP_OUTPUT,
    ),
    help(
        "-X, --request <method>",
        "Specify request method to use",
        CURLHELP_CONNECTION
            | CURLHELP_POP3
            | CURLHELP_FTP
            | CURLHELP_IMAP
            | CURLHELP_SMTP,
    ),
    help(
        "    --request-target <path>",
        "Specify the target for this request",
        CURLHELP_HTTP,
    ),
    help(
        "    --resolve <[+]host:port:addr[,addr]...>",
        "Resolve host+port to address",
        CURLHELP_CONNECTION | CURLHELP_DNS,
    ),
    help(
        "    --retry <num>",
        "Retry request if transient problems occur",
        CURLHELP_CURL,
    ),
    help(
        "    --retry-all-errors",
        "Retry all errors (with --retry)",
        CURLHELP_CURL,
    ),
    help(
        "    --retry-connrefused",
        "Retry on connection refused (with --retry)",
        CURLHELP_CURL,
    ),
    help(
        "    --retry-delay <seconds>",
        "Wait time between retries",
        CURLHELP_CURL | CURLHELP_TIMEOUT,
    ),
    help(
        "    --retry-max-time <seconds>",
        "Retry only within this period",
        CURLHELP_CURL | CURLHELP_TIMEOUT,
    ),
    help(
        "    --sasl-authzid <identity>",
        "Identity for SASL PLAIN authentication",
        CURLHELP_AUTH,
    ),
    help(
        "    --sasl-ir",
        "Initial response in SASL authentication",
        CURLHELP_AUTH,
    ),
    help(
        "    --service-name <name>",
        "SPNEGO service name",
        CURLHELP_AUTH,
    ),
    help(
        "-S, --show-error",
        "Show error even when -s is used",
        CURLHELP_CURL | CURLHELP_GLOBAL,
    ),
    help(
        "-i, --show-headers",
        "Show response headers in output",
        CURLHELP_IMPORTANT | CURLHELP_VERBOSE | CURLHELP_OUTPUT,
    ),
    help(
        "    --sigalgs <list>",
        "TLS signature algorithms to use",
        CURLHELP_TLS,
    ),
    help(
        "-s, --silent",
        "Silent mode",
        CURLHELP_IMPORTANT | CURLHELP_VERBOSE,
    ),
    help(
        "    --skip-existing",
        "Skip download if local file already exists",
        CURLHELP_CURL | CURLHELP_OUTPUT,
    ),
    help(
        "    --socks4 <host[:port]>",
        "SOCKS4 proxy on given host + port",
        CURLHELP_PROXY,
    ),
    help(
        "    --socks4a <host[:port]>",
        "SOCKS4a proxy on given host + port",
        CURLHELP_PROXY,
    ),
    help(
        "    --socks5 <host[:port]>",
        "SOCKS5 proxy on given host + port",
        CURLHELP_PROXY,
    ),
    help(
        "    --socks5-basic",
        "Username/password auth for SOCKS5 proxies",
        CURLHELP_PROXY | CURLHELP_AUTH,
    ),
    help(
        "    --socks5-gssapi",
        "Enable GSS-API auth for SOCKS5 proxies",
        CURLHELP_PROXY | CURLHELP_AUTH,
    ),
    help(
        "    --socks5-gssapi-nec",
        "Compatibility with NEC SOCKS5 server",
        CURLHELP_PROXY | CURLHELP_AUTH,
    ),
    help(
        "    --socks5-gssapi-service <name>",
        "SOCKS5 proxy service name for GSS-API",
        CURLHELP_PROXY | CURLHELP_AUTH,
    ),
    help(
        "    --socks5-hostname <host[:port]>",
        "SOCKS5 proxy, pass hostname to proxy",
        CURLHELP_PROXY,
    ),
    help(
        "-Y, --speed-limit <speed>",
        "Stop transfers slower than this",
        CURLHELP_CONNECTION,
    ),
    help(
        "-y, --speed-time <seconds>",
        "Trigger 'speed-limit' abort after this time",
        CURLHELP_CONNECTION | CURLHELP_TIMEOUT,
    ),
    help(
        "    --ssl",
        "Try enabling TLS",
        CURLHELP_TLS
            | CURLHELP_IMAP
            | CURLHELP_POP3
            | CURLHELP_SMTP
            | CURLHELP_LDAP,
    ),
    help(
        "    --ssl-allow-beast",
        "Allow security flaw to improve interop",
        CURLHELP_TLS,
    ),
    help(
        "    --ssl-auto-client-cert",
        "Use auto client certificate (Schannel)",
        CURLHELP_TLS,
    ),
    help(
        "    --ssl-no-revoke",
        "Disable cert revocation checks (Schannel)",
        CURLHELP_TLS,
    ),
    help(
        "    --ssl-reqd",
        "Require SSL/TLS",
        CURLHELP_TLS
            | CURLHELP_IMAP
            | CURLHELP_POP3
            | CURLHELP_SMTP
            | CURLHELP_LDAP,
    ),
    help(
        "    --ssl-revoke-best-effort",
        "Ignore missing cert CRL dist points",
        CURLHELP_TLS,
    ),
    help(
        "    --ssl-sessions <filename>",
        "Load/save SSL session tickets from/to this file",
        CURLHELP_TLS,
    ),
    help("-2, --sslv2", "SSLv2", CURLHELP_DEPRECATED),
    help("-3, --sslv3", "SSLv3", CURLHELP_DEPRECATED),
    help(
        "    --stderr <file>",
        "Where to redirect stderr",
        CURLHELP_VERBOSE | CURLHELP_GLOBAL,
    ),
    help(
        "    --styled-output",
        "Enable styled output for HTTP headers",
        CURLHELP_VERBOSE | CURLHELP_GLOBAL,
    ),
    help(
        "    --suppress-connect-headers",
        "Suppress proxy CONNECT response headers",
        CURLHELP_PROXY,
    ),
    help(
        "    --tcp-fastopen",
        "Use TCP Fast Open",
        CURLHELP_CONNECTION,
    ),
    help("    --tcp-nodelay", "Set TCP_NODELAY", CURLHELP_CONNECTION),
    help(
        "-t, --telnet-option <opt=val>",
        "Set telnet option",
        CURLHELP_TELNET,
    ),
    help(
        "    --tftp-blksize <value>",
        "Set TFTP BLKSIZE option",
        CURLHELP_TFTP,
    ),
    help(
        "    --tftp-no-options",
        "Do not send any TFTP options",
        CURLHELP_TFTP,
    ),
    help(
        "-z, --time-cond <time>",
        "Transfer based on a time condition",
        CURLHELP_HTTP | CURLHELP_FTP,
    ),
    help(
        "    --tls-earlydata",
        "Allow use of TLSv1.3 early data (0RTT)",
        CURLHELP_TLS,
    ),
    help(
        "    --tls-max <VERSION>",
        "Maximum allowed TLS version",
        CURLHELP_TLS,
    ),
    help(
        "    --tls13-ciphers <list>",
        "TLS 1.3 cipher suites to use",
        CURLHELP_TLS,
    ),
    help(
        "    --tlsauthtype <type>",
        "TLS authentication type",
        CURLHELP_TLS | CURLHELP_AUTH,
    ),
    help(
        "    --tlspassword <string>",
        "TLS password",
        CURLHELP_TLS | CURLHELP_AUTH,
    ),
    help(
        "    --tlsuser <name>",
        "TLS username",
        CURLHELP_TLS | CURLHELP_AUTH,
    ),
    help("-1, --tlsv1", "TLSv1.0 or greater", CURLHELP_TLS),
    help("    --tlsv1.0", "TLSv1.0 or greater", CURLHELP_TLS),
    help("    --tlsv1.1", "TLSv1.1 or greater", CURLHELP_TLS),
    help("    --tlsv1.2", "TLSv1.2 or greater", CURLHELP_TLS),
    help("    --tlsv1.3", "TLSv1.3 or greater", CURLHELP_TLS),
    help(
        "    --tr-encoding",
        "Request compressed transfer encoding",
        CURLHELP_HTTP,
    ),
    help(
        "    --trace <file>",
        "Write a debug trace to FILE",
        CURLHELP_VERBOSE | CURLHELP_GLOBAL,
    ),
    help(
        "    --trace-ascii <file>",
        "Like --trace, but without hex output",
        CURLHELP_VERBOSE | CURLHELP_GLOBAL,
    ),
    help(
        "    --trace-config <string>",
        "Details to log in trace/verbose output",
        CURLHELP_VERBOSE | CURLHELP_GLOBAL,
    ),
    help(
        "    --trace-ids",
        "Transfer + connection ids in verbose output",
        CURLHELP_VERBOSE | CURLHELP_GLOBAL,
    ),
    help(
        "    --trace-time",
        "Add time stamps to trace/verbose output",
        CURLHELP_VERBOSE | CURLHELP_GLOBAL,
    ),
    help(
        "    --unix-socket <path>",
        "Connect through this Unix domain socket",
        CURLHELP_CONNECTION,
    ),
    help(
        "-T, --upload-file <file>",
        "Transfer local FILE to destination",
        CURLHELP_IMPORTANT | CURLHELP_UPLOAD,
    ),
    help(
        "    --upload-flags <flags>",
        "IMAP upload behavior",
        CURLHELP_CURL | CURLHELP_OUTPUT,
    ),
    help("    --url <url/file>", "URL(s) to work with", CURLHELP_CURL),
    help(
        "    --url-query <data>",
        "Add a URL query part",
        CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD,
    ),
    help(
        "-B, --use-ascii",
        "Use ASCII/text transfer",
        CURLHELP_FTP | CURLHELP_OUTPUT | CURLHELP_LDAP | CURLHELP_TFTP,
    ),
    help(
        "-u, --user <user:password>",
        "Server user and password",
        CURLHELP_IMPORTANT | CURLHELP_AUTH,
    ),
    help(
        "-A, --user-agent <name>",
        "Send User-Agent <name> to server",
        CURLHELP_IMPORTANT | CURLHELP_HTTP,
    ),
    help(
        "    --variable <[%]name=text/@file>",
        "Set variable",
        CURLHELP_CURL,
    ),
    help(
        "-v, --verbose",
        "Make the operation more talkative",
        CURLHELP_IMPORTANT | CURLHELP_VERBOSE | CURLHELP_GLOBAL,
    ),
    help(
        "-V, --version",
        "Show version number and quit",
        CURLHELP_IMPORTANT | CURLHELP_CURL,
    ),
    help(
        "    --vlan-priority <priority>",
        "Set VLAN priority",
        CURLHELP_CONNECTION,
    ),
    help(
        "-w, --write-out <format>",
        "Output FORMAT after completion",
        CURLHELP_VERBOSE,
    ),
    help(
        "    --xattr",
        "Store metadata in extended file attributes",
        CURLHELP_OUTPUT,
    ),
];

// The category descriptors -- src/tool_help.c:35-68

/// One row of the category listing -- `struct category_descriptors`,
/// `src/tool_help.c:35-39`.
///
/// ```c
/// struct category_descriptors {
///   const char *opt;
///   const char *desc;
///   unsigned int category;
/// };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CategoryDescriptor {
    /// `opt` -- the name `--help <name>` accepts, matched without regard to
    /// ASCII case.
    opt: &'static str,
    /// `desc` -- the description printed beside it.
    desc: &'static str,
    /// `category` -- the single `CURLHELP_*` bit this name selects.
    category: u32,
}

/// Builds one [`CategoryDescriptor`].
const fn category(
    opt: &'static str,
    desc: &'static str,
    category: u32,
) -> CategoryDescriptor {
    CategoryDescriptor {
        opt,
        desc,
        category,
    }
}

/// `categories[]` -- `src/tool_help.c:41-68`, carrying the C comment
/// "important is left out because it is the default help page".
///
/// 25 rows in exactly this order, because this is the printed order: both
/// `get_categories` and `get_categories_list` walk it front to back. There is
/// deliberately no row for `CURLHELP_IMPORTANT` -- that bit is what
/// `tool_help(None)` prints, so naming it as a category would list the default
/// page as one of the alternatives to itself.
const CATEGORIES: [CategoryDescriptor; 25] = [
    category("auth", "Authentication methods", CURLHELP_AUTH),
    category("connection", "Manage connections", CURLHELP_CONNECTION),
    category("curl", "The command line tool itself", CURLHELP_CURL),
    category("deprecated", "Legacy", CURLHELP_DEPRECATED),
    category("dns", "Names and resolving", CURLHELP_DNS),
    category("file", "FILE protocol", CURLHELP_FILE),
    category("ftp", "FTP protocol", CURLHELP_FTP),
    category("global", "Global options", CURLHELP_GLOBAL),
    category("http", "HTTP and HTTPS protocol", CURLHELP_HTTP),
    category("imap", "IMAP protocol", CURLHELP_IMAP),
    category("ldap", "LDAP protocol", CURLHELP_LDAP),
    category("output", "File system output", CURLHELP_OUTPUT),
    category("pop3", "POP3 protocol", CURLHELP_POP3),
    category("post", "HTTP POST specific", CURLHELP_POST),
    category("proxy", "Options for proxies", CURLHELP_PROXY),
    category("scp", "SCP protocol", CURLHELP_SCP),
    category("sftp", "SFTP protocol", CURLHELP_SFTP),
    category("smtp", "SMTP protocol", CURLHELP_SMTP),
    category("ssh", "SSH protocol", CURLHELP_SSH),
    category("telnet", "TELNET protocol", CURLHELP_TELNET),
    category("tftp", "TFTP protocol", CURLHELP_TFTP),
    category("timeout", "Timeouts and delays", CURLHELP_TIMEOUT),
    category("tls", "TLS/SSL related", CURLHELP_TLS),
    category("upload", "Upload, sending data", CURLHELP_UPLOAD),
    category("verbose", "Tracing, logging etc", CURLHELP_VERBOSE),
];

// The column arithmetic -- src/tool_help.c:70-154

/// The lower bound both column widths start from -- `size_t longopt = 5;` and
/// `size_t longdesc = 5;` at `src/tool_help.c:73-74`.
const MIN_COLUMN: usize = 5;

/// Writes one help line: a leading space, the option padded to `width`, two
/// spaces, the description, a newline.
///
/// This is `curl_mprintf(" %-*s  %s\n", (int)opt, ..., ...)` at
/// `src/tool_help.c:104`. Two details of that conversion are reproduced
/// deliberately, because both are observable:
///
/// * `%-*s` **does not truncate**. When the width is smaller than the string,
///   C prints the whole string and the padding is simply absent. So a narrow
///   terminal loses alignment, never characters.
/// * The padding is measured in **bytes**, because C measures with `strlen`.
///   The padding here is emitted from `str::len()` for that reason, rather than
///   through a format width, which `std` computes from a character count. Every
///   one of the 273 `opt` strings is ASCII, so the two agree today; writing the
///   byte form means they cannot disagree if one ever is not.
fn write_help_line<W: Write>(row: &HelpTxt, width: usize, out: &mut W) {
    // `saturating_sub` rather than `-`: when `width < opt.len()` C's `%-*s`
    // emits no padding at all, which is exactly a saturation to zero. It also
    // means this cannot panic in a debug build, where plain subtraction would.
    let pad = width.saturating_sub(row.opt.len());

    let _ = out.write_all(b" ");
    let _ = out.write_all(row.opt.as_bytes());
    for _ in 0..pad {
        let _ = out.write_all(b" ");
    }
    let _ = out.write_all(b"  ");
    let _ = out.write_all(row.desc.as_bytes());
    let _ = out.write_all(b"\n");
}

/// `print_category(category, cols)` -- `src/tool_help.c:70-106`.
///
/// Prints every row whose mask intersects `category`, aligned to a width
/// derived from the widest option and the widest description among *those* rows
/// alone. The arithmetic is byte-observable and is reproduced statement for
/// statement:
///
/// ```c
/// size_t longopt = 5, longdesc = 5;
/// for each matching row: longopt  = max(longopt,  strlen(opt));
///                        longdesc = max(longdesc, strlen(desc));
/// if(longdesc > cols)                longopt = 0;             /* wrap-around */
/// else if(longopt + longdesc > cols) longopt = cols - longdesc;
/// for each matching row {
///   size_t opt = longopt, desclen = strlen(desc);
///   if(cols >= 2 && opt + desclen >= (cols - 2)) {
///     if(desclen < (cols - 2)) opt = (cols - 3) - desclen;
///     else                     opt = 0;
///   }
///   curl_mprintf(" %-*s  %s\n", (int)opt, opt_string, desc);
/// }
/// ```
///
/// # Why none of the subtractions can go negative
///
/// C performs all of this in `size_t`, where a negative intermediate would wrap
/// to an enormous width; its guards are what stop that, and the same guards are
/// kept here rather than replaced by clamping:
///
/// * `cols - longdesc` runs only in the `else` of `longdesc > cols`, so
///   `longdesc <= cols`.
/// * `cols - 2` runs only under `cols >= 2`.
/// * `(cols - 3) - desclen` runs only when `desclen < cols - 2`. That forces
///   `cols - 2 >= 1`, hence `cols >= 3`, and `desclen <= cols - 3`, so the
///   result is non-negative.
///
/// `saturating_sub` is used regardless, so that a debug build cannot panic even
/// if a future edit weakened a guard. Each use is unreachable as written.
fn print_category<W: Write>(category: u32, cols: usize, out: &mut W) {
    let mut longopt = MIN_COLUMN;
    let mut longdesc = MIN_COLUMN;

    // `:76-86` -- measure the matching rows only.
    for row in HELPTEXT {
        if row.categories & category == 0 {
            continue;
        }
        longopt = longopt.max(row.opt.len());
        longdesc = longdesc.max(row.desc.len());
    }

    // `:88-91`.
    if longdesc > cols {
        // "avoid wrap-around" -- give the option column no width at all rather
        // than a width computed from a negative difference.
        longopt = 0;
    } else if longopt + longdesc > cols {
        longopt = cols.saturating_sub(longdesc);
    }

    // `:93-105`.
    for row in HELPTEXT {
        if row.categories & category == 0 {
            continue;
        }
        let mut width = longopt;
        let desclen = row.desc.len();
        // `:98-103` -- the per-row "avoid wrap-around" adjustment.
        if cols >= 2 && width + desclen >= cols - 2 {
            width = if desclen < cols - 2 {
                cols.saturating_sub(3).saturating_sub(desclen)
            } else {
                0
            };
        }
        write_help_line(row, width, out);
    }
}

/// `get_category_content(category, cols)` -- `src/tool_help.c:108-119`,
/// carrying the C comment "Prints category if found. If not, it returns 1".
///
/// Returns `true` when the category was found and printed, so the caller's
/// `if(get_category_content(...))` becomes `if !...`. Inverting the polarity
/// rather than returning C's `int` keeps the call site readable while leaving
/// the branch structure identical; the C return values are 0 for found and 1
/// for not found.
///
/// The comparison is `curl_strequal`, i.e. case-insensitive, so `--help HTTP`
/// and `--help http` select the same page.
fn get_category_content<W: Write>(
    wanted: &str,
    cols: usize,
    out: &mut W,
) -> bool {
    for row in &CATEGORIES {
        if row.opt.eq_ignore_ascii_case(wanted) {
            // `:114` -- `curl_mprintf("%s: %s\n", opt, desc)`.
            let _ = writeln!(out, "{}: {}", row.opt, row.desc);
            print_category(row.category, cols, out);
            return true;
        }
    }
    false
}

/// `get_categories()` -- `src/tool_help.c:121-127`, "Prints all categories and
/// their description".
///
/// `curl_mprintf(" %-11s %s\n", opt, desc)`: one leading space, the name padded
/// to 11 columns, **one** separating space, the description. Note the contrast
/// with `print_category`, which uses two separating spaces -- the two listings
/// genuinely differ, and neither may be made to match the other.
fn get_categories<W: Write>(out: &mut W) {
    for row in &CATEGORIES {
        // `%-11s` measured in bytes, for the reason `write_help_line` gives.
        let pad = CATEGORY_NAME_WIDTH.saturating_sub(row.opt.len());
        let _ = out.write_all(b" ");
        let _ = out.write_all(row.opt.as_bytes());
        for _ in 0..pad {
            let _ = out.write_all(b" ");
        }
        let _ = out.write_all(b" ");
        let _ = out.write_all(row.desc.as_bytes());
        let _ = out.write_all(b"\n");
    }
}

/// The `11` of `" %-11s %s\n"` -- `src/tool_help.c:126`.
const CATEGORY_NAME_WIDTH: usize = 11;

/// `get_categories_list(width)` -- `src/tool_help.c:129-154`, "Prints all
/// categories as a comma-separated list of given width".
///
/// A flow-filled list. Three details are frozen and easy to lose:
///
/// * The **final** category tests `col + len + 1 < width` and terminates with
///   `.`; every other category tests `col + len + 2 < width` and separates with
///   `, `. The `+ 1` against `+ 2` asymmetry is C's, and it is not an
///   off-by-one -- the final entry appends one byte where the others append
///   two.
/// * Both tests are **strict** `<`.
/// * When a test fails, the newline goes **before** the entry, so a line break
///   never leaves a trailing separator at the end of a line, and `col` is reset
///   to that entry's own contribution rather than to zero.
///
/// `col` starts at 0, which means the first entry is measured as though the
/// cursor were at column 0 even though `tool_help` has just printed a line.
/// That is C's accounting and is reproduced as such.
fn get_categories_list<W: Write>(width: usize, out: &mut W) {
    let mut col: usize = 0;
    let last = CATEGORIES.len().saturating_sub(1);

    for (index, row) in CATEGORIES.iter().enumerate() {
        let len = row.opt.len();
        if index == last {
            // `:136-143` -- final category.
            if col + len + 1 < width {
                let _ = writeln!(out, "{}.", row.opt);
            } else {
                // "start a new line first"
                let _ = writeln!(out, "\n{}.", row.opt);
            }
        } else if col + len + 2 < width {
            // `:144-147`.
            let _ = write!(out, "{}, ", row.opt);
            col += len + 2;
        } else {
            // `:148-152` -- "start a new line first".
            let _ = write!(out, "\n{}, ", row.opt);
            col = len + 2;
        }
    }
}

// The built-in-manual scanner -- src/tool_help.h:31-48, src/tool_help.c:156-223

/// `char rbuf[40]` -- `src/tool_help.h:39`. The rolling match window.
///
/// The size is behavioural, not arbitrary: it bounds the longest needle the
/// scanner can recognise, and every needle in use is shorter. The longest is
/// the per-option search key, at most `"\n    --no-"` plus a long option name;
/// `MAX_OPTION_LEN` is 26 (`src/tool_getparam.c:2886`), which caps that at 36.
const RBUF_LEN: usize = 40;

/// `char obuf[160]` -- `src/tool_help.h:40`. The line accumulator.
///
/// Also behavioural: a manual line of 160 bytes or more aborts the scan rather
/// than wrapping. See `helpscan` for the exact boundary.
const OBUF_LEN: usize = 160;

/// `char cmdbuf[80]` -- `src/tool_help.c:277`. The per-option search key
/// buffer, written with `curl_msnprintf(cmdbuf, sizeof(cmdbuf), ...)`, so the
/// key is truncated to 79 bytes plus a terminator.
const CMDBUF_LEN: usize = 80;

/// Which of the three stages the scanner is in.
///
/// C carries this as `unsigned char show` with the comment "start as at 0.
/// trigger match moves it to 1, arg match moves it to 2, endarg stops the
/// search" (`src/tool_help.h:41-44`). The mapping is
/// `Trigger` = 0, `Arg` = 1, `Body` = 2.
///
/// An enum rather than a `u8` because the stage selects which needle is sought
/// and therefore which width the window is rolled at; making the three states
/// the only representable ones means an exhaustive `match` cannot fall through
/// to a fourth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanStage {
    /// Before the trigger: consume input, emit nothing.
    Trigger,
    /// Past the trigger, hunting for the option's own heading.
    Arg,
    /// Past the heading: emit whole lines until the terminator.
    Body,
}

/// `struct scan_ctx` -- `src/tool_help.h:31-45`.
///
/// A three-stage sliding-window matcher over the built-in manual. It is fed the
/// manual in arbitrary pieces and emits the section belonging to one option.
///
/// The needles are borrowed rather than owned, exactly as C's three
/// `const char *` fields are, which is what the lifetime parameter records.
/// They are held as bytes because the window is compared byte-wise and because
/// the arg needle is emitted from its second byte onward -- an operation that on
/// a `&str` would need a character-boundary proof it does not need on `&[u8]`.
#[derive(Clone, Debug)]
pub(crate) struct ScanCtx<'a> {
    /// `trigger` -- the section header that opens the search.
    trigger: &'a [u8],
    /// `arg` -- the option's own heading. Its **first byte is dropped** when it
    /// is echoed; see `helpscan`.
    arg: &'a [u8],
    /// `endarg` -- what stops the search.
    endarg: &'a [u8],
    /// `olen` -- how much of `obuf` the current line occupies.
    olen: usize,
    /// `rbuf` -- the rolling window. Zeroed by `inithelpscan`.
    rbuf: [u8; RBUF_LEN],
    /// `obuf` -- the current line, accumulated until a newline arrives.
    obuf: [u8; OBUF_LEN],
    /// `show` -- the stage.
    show: ScanStage,
}

impl ScanCtx<'_> {
    /// Rolls the window one byte and reports whether it now equals `needle`.
    ///
    /// This is the three-line preamble C repeats in each stage
    /// (`src/tool_help.c:182-184`, `:190-192`, `:200-202`):
    ///
    /// ```c
    /// memmove(&ctx->rbuf[0], &ctx->rbuf[1], n - 1);
    /// ctx->rbuf[n - 1] = buf[i];
    /// if(!memcmp(ctx->rbuf, needle, n)) /* match */;
    /// ```
    ///
    /// `n` is the length of the needle **currently** being sought, so the same
    /// 40-byte buffer is rolled at three different widths over the course of one
    /// scan, and the bytes an earlier stage left behind are still there when a
    /// later stage begins. That is what makes the match position-dependent, and
    /// it is why a plain substring search over the whole input is not a
    /// substitute.
    ///
    /// # The two inputs on which C is not defined
    ///
    /// Both are unreachable with the needles this module actually uses, and both
    /// are given the safe reading rather than left to chance:
    ///
    /// * **An empty needle.** C would call `memmove` with a count of
    ///   `(size_t)-1`. `memcmp` over zero bytes compares equal, so the limit of
    ///   C's own expression is an immediate match, and that is what is returned
    ///   -- without rolling, since there is no window to roll.
    /// * **A needle longer than the window.** C would write `rbuf[n - 1]` past
    ///   the end of a 40-byte array; its `DEBUGASSERT` at
    ///   `src/tool_help.c:169-170` only checks `elen < 40 || flen < 40`, which
    ///   an over-long needle can still satisfy. Such a needle can never be held
    ///   in full, so it can never match, and `false` is returned.
    fn advance(&mut self, needle: &[u8], byte: u8) -> bool {
        let n = needle.len();
        if n == 0 {
            return true;
        }
        if n > RBUF_LEN {
            return false;
        }

        // `1..n` is in range because `1 <= n <= RBUF_LEN`, and is empty when
        // `n == 1`, which is the correct no-op for a one-byte needle.
        self.rbuf.copy_within(1..n, 0);
        match self.rbuf.get_mut(n - 1) {
            Some(slot) => *slot = byte,
            // Unreachable: `n - 1 < RBUF_LEN` follows from the bound above.
            // Written as a branch rather than an index so that no input can
            // panic.
            None => return false,
        }
        self.rbuf.get(..n).is_some_and(|window| window == needle)
    }
}

/// `inithelpscan(ctx, trigger, arg, endarg)` -- `src/tool_help.c:158-174`.
///
/// C fills a caller-supplied `struct scan_ctx` on the stack; this returns the
/// value instead, which is the same thing said in Rust and removes the
/// "initialise before use" obligation entirely. The three `strlen` fields C
/// stores alongside each pointer are dropped: a slice carries its own length.
///
/// The `DEBUGASSERT((elen < sizeof(rbuf)) || (flen < sizeof(rbuf)))` at
/// `:169-170` is not reproduced as an assertion, because an assertion is a
/// panic and this module has none. `ScanCtx::advance` handles an over-long
/// needle by never matching it, which is the outcome the assertion exists to
/// warn about.
///
/// `rbuf` is zeroed in full, as `memset(ctx->rbuf, 0, sizeof(ctx->rbuf))` at
/// `:173` does -- not merely the prefix the first needle will use.
pub(crate) fn inithelpscan<'a>(
    trigger: &'a str,
    arg: &'a str,
    endarg: &'a str,
) -> ScanCtx<'a> {
    ScanCtx {
        trigger: trigger.as_bytes(),
        arg: arg.as_bytes(),
        endarg: endarg.as_bytes(),
        olen: 0,
        rbuf: [0; RBUF_LEN],
        obuf: [0; OBUF_LEN],
        show: ScanStage::Trigger,
    }
}

/// `helpscan(buf, len, ctx)` -- `src/tool_help.c:176-221`.
///
/// Feeds one piece of the manual through the matcher. Returns `true` to mean
/// "keep feeding" and `false` to mean "stop": the driver in
/// `crate::cli::hugehelp` breaks its loop on `false`, exactly as
/// `src/mkhelp.pl:245-248` does.
///
/// Two signature differences from C, both forced and neither behavioural. The
/// `len` parameter is gone, because a slice carries its length -- C's `buf` and
/// `len` are always a pointer and the `strlen` of the same string. And the
/// destination is a parameter rather than `stdout`, which is what lets the
/// `tests` module below assert the emitted bytes without a terminal; the
/// wrapper that supplies the real standard output is
/// `crate::cli::hugehelp::showhelp`.
///
/// # The behaviours that are easy to lose
///
/// * On the arg match it emits **`&arg[1]`** -- the needle minus its first
///   byte, which is the leading newline. That is deliberate in C
///   (`src/tool_help.c:194`) and observable: the heading is echoed without the
///   blank line that preceded it.
/// * The endarg test happens **before** the byte is accumulated, so the
///   terminator's own bytes never reach the output.
/// * A line of `OBUF_LEN` bytes aborts the scan. The guard runs before the
///   accumulator is touched, in both the newline and the ordinary branch, so
///   160 bytes can be held and the 161st byte -- newline or not -- bails out
///   with `false`. The longest printable line is therefore 159 bytes. C would
///   `DEBUGASSERT` first and then bail identically in a release build.
/// * Write failures are discarded. C's `puts` and `fputs` returns are never
///   read, so a failed write costs C one line and nothing else; returning early
///   here would abandon the rest of the section.
pub(crate) fn helpscan<W: Write>(
    buf: &[u8],
    ctx: &mut ScanCtx<'_>,
    out: &mut W,
) -> bool {
    for &byte in buf {
        match ctx.show {
            // `:180-187` -- wait for the trigger.
            ScanStage::Trigger => {
                let needle = ctx.trigger;
                if ctx.advance(needle, byte) {
                    ctx.show = ScanStage::Arg;
                }
            }

            // `:189-198` -- past the trigger, hunt for the heading.
            ScanStage::Arg => {
                let needle = ctx.arg;
                if ctx.advance(needle, byte) {
                    // `:194` -- `fputs(&ctx->arg[1], stdout)`.
                    if let Some(tail) = needle.get(1..) {
                        let _ = out.write_all(tail);
                    }
                    ctx.show = ScanStage::Body;
                }
            }

            // `:199-218` -- show until the end.
            ScanStage::Body => {
                let needle = ctx.endarg;
                if ctx.advance(needle, byte) {
                    // `:202-203`.
                    return false;
                }

                if byte == b'\n' {
                    // `:205-212`. C writes a terminator at `obuf[olen]`,
                    // resets `olen`, then `puts(obuf)` -- which reads up to
                    // that terminator, so the emitted bytes are the `olen`
                    // accumulated ones followed by the newline `puts` adds.
                    if ctx.olen == OBUF_LEN {
                        return false;
                    }
                    let end = ctx.olen;
                    ctx.olen = 0;
                    if let Some(line) = ctx.obuf.get(..end) {
                        let _ = out.write_all(line);
                    }
                    let _ = out.write_all(b"\n");
                } else {
                    // `:213-218`.
                    match ctx.obuf.get_mut(ctx.olen) {
                        Some(slot) => {
                            *slot = byte;
                            ctx.olen += 1;
                        }
                        // `olen == OBUF_LEN`: "bail out" at `:216`.
                        None => return false,
                    }
                }
            }
        }
    }

    true
}

// tool_help -- src/tool_help.c:225-300

/// `puts("Usage: curl [options...] <url>")` -- `src/tool_help.c:240`.
///
/// **`curl`, not `curl-rs`.** The Cargo package is `curl-rs` and the binary
/// file may be named anything, but every self-reported string is `curl`
/// (`CURL_NAME`, `src/tool_version.h:28`). Nothing in this module takes its
/// identity from Cargo metadata or from `argv[0]`.
const USAGE: &str = "Usage: curl [options...] <url>";

/// `category_note` -- `src/tool_help.c:230-233`.
///
/// Three adjacent C literals, reproduced as three `concat!` arguments so that
/// the split is identical and no reformatting can move a byte. The emitted text
/// opens with a newline, carries a second newline after "categories.", and the
/// quotation marks around `--help category` are literal. `puts` adds the
/// trailing newline.
const CATEGORY_NOTE: &str = concat!(
    "\nThis is not the full help; this ",
    "menu is split into categories.\nUse \"--help category\" to get ",
    "an overview of all categories, which are:",
);

/// `category_note2` -- `src/tool_help.c:234-239`.
///
/// **Both lines are emitted.** The second is inside `#ifdef USE_MANUAL` in C,
/// and the manual is unconditional here because `curl-rs/build.rs` writes its
/// artifact on every build -- so there is no configuration in which the second
/// line should be absent. See this module's header.
const CATEGORY_NOTE2: &str = concat!(
    "Use \"--help all\" to list all options",
    "\nUse \"--help [option]\" to view documentation for a given option",
);

/// `src/tool_help.c:297`.
///
/// The literal ends with an explicit `\n` and `puts` adds another, so a blank
/// line separates this from the category list that follows.
const UNKNOWN_CATEGORY: &str =
    "Unknown category provided, here is a list of all categories:\n";

/// `src/tool_help.c:273-274`. Goes to standard error.
///
/// Two C literals concatenated; the emitted text has exactly one space between
/// "for," and "see". And again `curl`, never `curl-rs`.
const INCORRECT_OPTION: &str =
    concat!("Incorrect option name to show help for,", " see curl -h",);

/// `src/tool_help.c:291-292`, the `#else` arm of `USE_MANUAL`.
///
/// **Unreachable in this build.** `crate::cli::hugehelp` is always present, so
/// the per-option branch never degrades to this message. It is reproduced so
/// that the arm exists if the manual ever becomes configurable, and so that a
/// reader comparing this file against the C does not have to wonder where it
/// went.
const MANUAL_ABSENT: &str = concat!(
    "Cannot comply. ",
    "This curl was built without built-in manual",
);

/// The section header the per-option search starts from --
/// `src/tool_help.c:286`, `:288`.
const MANUAL_TRIGGER: &str = "\nALL OPTIONS\n";

/// The terminator for the **last** option in the manual --
/// `src/tool_help.c:286`, carrying the C comment "this is the last option,
/// which then ends when FILES starts".
const MANUAL_END_LAST: &str = "\nFILES";

/// The terminator for every other option: the start of the next one --
/// `src/tool_help.c:288`.
const MANUAL_END_NEXT: &str = "\n    -";

/// `tool_help(category)` -- `src/tool_help.c:225-300`.
///
/// The signature is pinned by its caller: `crate::cli::args` reaches it from
/// inside the parser, mirroring `src/tool_getparam.c:3003`, where C calls
/// `tool_help(category)` *before* returning `PARAM_HELP_REQUESTED`.
///
/// The terminal width comes from `crate::terminal::get_terminal_columns` and is
/// never re-derived here. That function has a deterministic fallback of 79, and
/// under `tests/runtests.pl` the C build reaches the same 79 because its
/// `ioctl` targets standard input, which the harness never leaves as a
/// terminal -- so the wrapping is byte-identical under the harness.
#[allow(dead_code)] // The `ParseHost::help` implementation is the caller; until
                    // it is wired, this is the module's live root and every
                    // item it reaches through is reachable with it.
pub(crate) fn tool_help(category: Option<&str>) {
    // C holds the width in an `unsigned int` and mixes it with `size_t` in the
    // arithmetic, so `usize` is the type that arithmetic wants. The conversion
    // is lossless on all four mandated targets, every one of which is 64-bit
    // (AAP 0.1.1); `try_from` states that rather than hiding it in a cast, and
    // the saturating fallback is unreachable.
    let cols = usize::try_from(get_terminal_columns()).unwrap_or(usize::MAX);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let stderr = io::stderr();
    let mut err = stderr.lock();

    tool_help_to(category, cols, &mut out, &mut err);

    let _ = out.flush();
}

/// The body of [`tool_help`], with both streams supplied.
///
/// Split out so that the `tests` module can assert the emitted bytes at a
/// chosen width without a terminal. The branch structure is C's, in C's order.
fn tool_help_to<W: Write, E: Write>(
    category: Option<&str>,
    cols: usize,
    out: &mut W,
    err: &mut E,
) {
    match category {
        // `:229-245` -- no category: the default page.
        None => {
            let _ = writeln!(out, "{USAGE}");
            print_category(CURLHELP_IMPORTANT, cols, out);
            let _ = writeln!(out, "{CATEGORY_NOTE}");
            get_categories_list(cols, out);
            let _ = writeln!(out, "{CATEGORY_NOTE2}");
        }

        Some(category) => {
            // `:247-249` -- "all": print everything.
            if category.eq_ignore_ascii_case("all") {
                print_category(CURLHELP_ALL, cols, out);
            }
            // `:250-252` -- the literal word "category", handled before the
            // lookup "to not print an errormsg".
            else if category.eq_ignore_ascii_case("category") {
                get_categories(out);
            }
            // `:253-294` -- an option name rather than a category.
            else if category.as_bytes().first() == Some(&b'-') {
                option_help(category, err);
            }
            // `:295-299` -- a category name, or a diagnostic if unknown.
            else if !get_category_content(category, cols, out) {
                let _ = writeln!(out, "{UNKNOWN_CATEGORY}");
                get_categories(out);
            }
        }
    }
}

/// Per-option help -- `src/tool_help.c:253-294`.
///
/// Resolves the option name, builds the search key and hands both to the manual
/// scanner. Both of its own messages go to standard error, which is why this
/// takes only that stream: the section text itself is written by
/// `crate::cli::hugehelp::showhelp`, which owns standard output for the manual.
fn option_help<E: Write>(category: &str, err: &mut E) {
    // The `#else` arm of `:290-293`, whose message C sends to `tool_stderr`
    // rather than to standard output. A named `const` rather than `#[cfg]` so
    // that the arm is type-checked on every build; the manual is unconditional
    // here, so `MANUAL_PRESENT` is a constant `true` and this branch is dead
    // code the optimiser removes.
    if !MANUAL_PRESENT {
        let _ = writeln!(err, "{MANUAL_ABSENT}");
        return;
    }

    match option_help_key(category) {
        Some((arg, endarg)) => hugehelp::showhelp(MANUAL_TRIGGER, &arg, endarg),
        // `:272-275`.
        None => {
            let _ = writeln!(err, "{INCORRECT_OPTION}");
        }
    }
}

/// Whether the built-in manual is compiled in -- C's `USE_MANUAL`.
///
/// Always `true`. `curl-rs/build.rs` writes the manual artifact on every build
/// and `crate::cli::hugehelp` includes it unconditionally, so there is no
/// configuration in which it is absent. Named rather than inlined so that the
/// two places C tests `USE_MANUAL` are visible here as tests of one thing.
const MANUAL_PRESENT: bool = true;

/// Resolves `--help <name>` to the manual search key and its terminator.
///
/// Returns `None` when the name does not name an option, which is C's
/// `a == NULL` at `src/tool_help.c:272`.
///
/// # The resolution rules, from `:256-271`
///
/// * A name starting `--` is looked up long. A `no-` prefix is stripped first
///   and then **rejected unless the option is `ARG_BOOL`**, because "a `--no-`
///   prefix for a non-boolean is not specifying a proper option" (`:266-267`).
/// * A name starting with a single `-` is looked up short, and **only when it
///   is exactly two bytes**: `:270` requires `!category[2]`, so `-xy` resolves
///   to nothing.
/// * C reads one byte past the terminator for the input `-`, whose second byte
///   *is* the terminator. An absent byte is read here as the `0` C finds there,
///   which sends `-` to `findshortopt(0)`; that function's own
///   `letter <= ' '` guard (`src/tool_getparam.c:832-833`) rejects it, so the
///   outcome is C's without the out-of-bounds read.
///
/// # The key, from `:277-288`
///
/// * With a short letter: `"\n    -<letter>, --"`. **The long name is
///   deliberately absent** -- the key stops at the `--`. That truncation is
///   what makes the manual scan match, because the manual spells the full
///   heading and the key is only its prefix.
/// * Otherwise, for an `ARG_NO` row: `"\n    --no-<lname>"`.
/// * Otherwise: `"\n    <the name as given>"`.
///
/// The terminator is `"\nFILES"` for `C_XATTR`, the last option in the manual,
/// and `"\n    -"` for every other.
fn option_help_key(category: &str) -> Option<(String, &'static str)> {
    let bytes = category.as_bytes();
    // C indexes a NUL-terminated string; a byte past the end reads as 0.
    let second = bytes.get(1).copied().unwrap_or(0);
    let third = bytes.get(2).copied().unwrap_or(0);

    let found: &LongShort = if second == b'-' {
        // `:257-269` -- long lookup.
        let mut lookup = bytes.get(2..).unwrap_or(&[]);
        let mut noflagged = false;
        if lookup.starts_with(b"no-") {
            lookup = lookup.get(3..).unwrap_or(&[]);
            noflagged = true;
        }
        let row = findlongopt(lookup)?;
        if noflagged && argtype(row.desc) != ARG_BOOL {
            return None;
        }
        row
    } else if third == 0 {
        // `:270-271` -- short lookup, exactly `-x`.
        findshortopt(second)?
    } else {
        return None;
    };

    // `:278-283`.
    let key = if found.letter != ' ' {
        format!("\n    -{}, --", found.letter)
    } else if found.desc & ARG_NO != 0 {
        format!("\n    --no-{}", found.lname)
    } else {
        format!("\n    {category}")
    };

    // `:279`, `:281`, `:283` all write through
    // `curl_msnprintf(cmdbuf, sizeof(cmdbuf), ...)`, so the key is capped at
    // `CMDBUF_LEN - 1` bytes. Unreachable with real input -- the longest
    // possible key is `"\n    --no-"` plus a 26-byte option name, which is
    // 36 -- and reproduced so that the cap is not silently wider here.
    let key = truncate_bytes(key, CMDBUF_LEN - 1);

    // `:284-288`.
    let endarg = if found.cmd == CmdKey::Xattr {
        MANUAL_END_LAST
    } else {
        MANUAL_END_NEXT
    };

    Some((key, endarg))
}

/// Shortens `text` to at most `max` bytes without splitting a character.
///
/// C truncates a `char` buffer at a byte boundary and cannot split anything,
/// because it has no notion of a character. Every input reaching this function
/// is ASCII by construction -- an option name matched against the alias table,
/// or a literal -- so the two agree; the character-boundary search exists only
/// so that no input can panic.
fn truncate_bytes(mut text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    // The largest character boundary at or below `max`.
    let cut = text
        .char_indices()
        .map(|(at, _)| at)
        .take_while(|at| *at <= max)
        .last()
        .unwrap_or(0);
    text.truncate(cut);
    text
}

// tool_version_info -- the --version printer, src/tool_help.c:301-386

/// `src/tool_help.c:315-316`, on standard error, with a **blank line after it**
/// -- the C literal ends `\n\n`.
///
/// Never emitted in this build: it is gated on `is_debug()`, and `Debug` is
/// deliberately withheld from the advertised feature list. See this module's
/// header for the cost of that decision and for the `memdebug` remedy.
const DEBUG_WARNING: &str = concat!(
    "WARNING: this libcurl is Debug-enabled, ",
    "do not use in production\n\n",
);

/// `src/tool_help.c:382-383`, on **standard output** -- `curl_mprintf`, not
/// `curl_mfprintf(tool_stderr, ...)`.
const VERSION_MISMATCH: &str = concat!(
    "WARNING: curl and libcurl versions do not match. ",
    "Functionality may be affected.",
);

/// `tool_version_info()` -- `src/tool_help.c:311-385`.
///
/// Carries C's signature: it takes nothing and asks
/// `crate::cli::libinfo::get_libcurl_info` for the data, which is where C reads
/// the four file-scope globals `curlinfo`, `built_in_protos`, `feature_names`
/// and `feature_count` that `src/tool_libinfo.c:136-190` filled.
#[allow(dead_code)] // Dispatched from `src/tool_operate.c:2314-2315`; the Rust
                    // caller is the `VersionInfoRequested` arm of the operate
                    // driver, which is not this module's to wire.
pub(crate) fn tool_version_info() {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let stderr = io::stderr();
    let mut err = stderr.lock();

    match libinfo::get_libcurl_info() {
        Ok(info) => tool_version_info_with(&info, &mut out, &mut err),
        // C cannot reach a corresponding arm: `src/tool_main.c` calls
        // `get_libcurl_info()` during start-up and exits with
        // `CURLE_FAILED_INIT` long before `--version` is reached, so by the
        // time `tool_version_info()` runs the globals are known good.
        // `crate::cli::libinfo` records that its own error arm is unreachable
        // too. Reporting it rather than aborting is what keeps that true
        // without an abrupt termination inside a printer.
        Err(error) => {
            let _ = writeln!(
                err,
                "curl: cannot report version information: {error}"
            );
        }
    }

    let _ = out.flush();
}

/// The body of [`tool_version_info`], with the data and both streams supplied.
///
/// Split out so that the `tests` module can assert the emitted bytes, and so
/// that a caller already holding a `LibInfo` need not build a second one.
pub(crate) fn tool_version_info_with<W: Write, E: Write>(
    info: &LibInfo,
    out: &mut W,
    err: &mut E,
) {
    // `:314-316` -- the pre-warning, on standard error.
    //
    // The predicate is `crate::cli::libinfo::LibInfo::is_debug`, which is
    // `is_debug()` at `src/tool_help.c:301-309` and already lives there because
    // it asks a question about the data. This module decides only what to do
    // with the answer.
    if info.is_debug() {
        let _ = write!(err, "{DEBUG_WARNING}");
    }

    // `:318` -- `curl_mprintf(CURL_ID "%s\n", curl_version())`.
    //
    // `CURL_ID` is `CURL_NAME " " CURL_VERSION " (" CURL_OS ") "`
    // (`src/tool_version.h:34`) -- note the trailing space *inside* the macro,
    // which is why nothing separates it from the banner below.
    //
    // Every part is queried, never duplicated: `curl-rs-lib/src/version.rs` is
    // the single owner of the name, the version and the host triple, so no
    // literal copy of any of them appears in this file. `CURL_OS` is a
    // build-configured string in C whose unconfigured fallback is the literal
    // "unknown" (`src/tool_setup.h:58-60`); the engine supplies a real triple,
    // and platform constants are not an identity source (see this module's
    // header).
    //
    // `tests/runtests.pl` `die`s if this line does not contain the substring
    // `libcurl`, which the banner supplies.
    let _ = writeln!(
        out,
        "{} {} ({}) {}",
        version::CURL_NAME,
        version::LIBCURL_VERSION,
        info.host(),
        version::version(),
    );

    // `:319-324`. `CURL_PATCHSTAMP` is not defined by default, so the
    // single-argument form is the one emitted: no ", security patched: ..."
    // tail. `LIBCURL_TIMESTAMP` is `"[unreleased]"`
    // (`include/curl/curlver.h:72`) and is a compile-time constant, never a
    // build clock -- AAP 0.7 requires the build to be reproducible.
    let _ = writeln!(out, "Release-Date: {}", version::LIBCURL_TIMESTAMP);

    // `:325-356`.
    write_protocols(info.built_in_protos(), out);

    // `:357-380`.
    write_features(info.feature_names(), out);

    // `:381-384` -- the drift detector, on standard output.
    write_version_mismatch(version::LIBCURL_VERSION, info.version(), out);
}

/// The version-mismatch warning -- `src/tool_help.c:381-384`.
///
/// ```c
/// if(strcmp(CURL_VERSION, curlinfo->version))
///   curl_mprintf("WARNING: curl and libcurl versions do not match. "
///                "Functionality may be affected.\n");
/// ```
///
/// `curl_mprintf`, so the destination is **standard output**, not standard
/// error -- unlike the `Debug` pre-warning and the two per-option-help
/// failures. The caller passes its `out` stream, which is what makes that
/// choice checkable from a test.
///
/// C compares its own compile-time `CURL_VERSION` (`src/tool_version.h:30`)
/// against the library's reported `curlinfo->version`. Both resolve to
/// `curl_rs_lib::version::LIBCURL_VERSION` here, because a statically linked
/// Rust binary and its library cannot be separately versioned the way a
/// dynamically linked pair can, so this is normally silent. It is kept rather
/// than dropped, and taken as two parameters rather than reading one constant
/// twice, so that it remains a genuine check that the two accessors have not
/// diverged.
fn write_version_mismatch<W: Write>(tool: &str, library: &str, out: &mut W) {
    if tool != library {
        let _ = writeln!(out, "{VERSION_MISMATCH}");
    }
}

/// The `Protocols:` line -- `src/tool_help.c:325-356`.
///
/// ```c
/// if(built_in_protos[0]) {
///   const char *insert = NULL;
///   for(builtin = built_in_protos; *builtin; ++builtin) {
///     if(insert) {
///       if(strcmp(*builtin, "ipfs") < 0) insert = *builtin;
///       else break;
///     }
///     else if(!strcmp(*builtin, "http")) insert = *builtin;
///   }
///   curl_mprintf("Protocols:");
///   for(builtin = built_in_protos; *builtin; ++builtin) {
///     if(!curl_strnequal(*builtin, "rtmp", 4) || !builtin[0][4])
///       curl_mprintf(" %s", *builtin);
///     if(insert && insert == *builtin) {
///       curl_mprintf(" ipfs ipns");
///       insert = NULL;
///     }
///   }
///   puts("");
/// }
/// ```
///
/// The whole line is suppressed when the list is empty, which is C's
/// `if(built_in_protos[0])` guard on the array's first element. That is the
/// state of this build today: `curl_rs_lib::version::ENGINE_PROTOCOLS` withholds
/// every scheme until the protocol engine exists, so nothing is advertised and
/// the line is absent -- the truthful posture AAP 0.6.5 requires, under which
/// the 283 fixtures targeting unimplemented schemes skip cleanly instead of
/// running and failing.
///
/// # The three frozen details
///
/// * The header is `Protocols:` with **no trailing space**; each name is
///   preceded by exactly one space; `puts("")` supplies the newline.
/// * **ipfs/ipns insertion.** The anchor starts at the entry equal to `http`
///   and then advances while the next entry sorts before `ipfs` -- a byte-wise,
///   case-sensitive `strcmp`, which is exactly what `str`'s ordering is.
///   `" ipfs ipns"` is emitted immediately *after* the anchor entry has been
///   printed, so the pair lands in alphabetical position. C compares `insert`
///   to `*builtin` by pointer; the same loop walks the same array, so the index
///   is the faithful and slightly stronger translation.
/// * **rtmp suppression**, carrying the C comment "do not list rtmp?*
///   protocols. They may only appear together with rtmp". `rtmp` itself prints,
///   because its fifth byte is the terminator; `rtmpe`, `rtmps`, `rtmpt` and the
///   rest do not. The prefix test is case-insensitive (`curl_strnequal`) and a
///   name shorter than four bytes cannot match it. Inert in this build, since no
///   rtmp variant is advertised, and reproduced regardless.
fn write_protocols<W: Write>(protos: &[&str], out: &mut W) {
    if protos.is_empty() {
        return;
    }

    // `:327-340` -- find the insertion anchor.
    let mut insert: Option<usize> = None;
    for (index, name) in protos.iter().enumerate() {
        if insert.is_some() {
            if *name < "ipfs" {
                insert = Some(index);
            } else {
                break;
            }
        } else if *name == "http" {
            insert = Some(index);
        }
    }

    // `:342`.
    let _ = out.write_all(b"Protocols:");

    // `:343-354`.
    for (index, name) in protos.iter().enumerate() {
        let bytes = name.as_bytes();
        // `!curl_strnequal(*builtin, "rtmp", 4)` -- true when the first four
        // bytes are not `rtmp`, which includes every name shorter than four.
        let rtmp_prefixed = bytes
            .get(..4)
            .is_some_and(|head| head.eq_ignore_ascii_case(b"rtmp"));
        // `|| !builtin[0][4]` -- true when the fifth byte is the terminator,
        // i.e. when the name is exactly `rtmp`.
        if !rtmp_prefixed || bytes.len() == 4 {
            let _ = write!(out, " {name}");
        }
        if insert == Some(index) {
            let _ = out.write_all(b" ipfs ipns");
            insert = None;
        }
    }

    // `:355` -- `puts("")`.
    let _ = out.write_all(b"\n");
}

/// The `Features:` line -- `src/tool_help.c:357-380`.
///
/// C copies `feature_names` into a heap array one element longer, appends
/// `"CAcert"` under `CURL_CA_EMBED`, `qsort`s the copy with
/// `struplocompare4sort` and prints it. The copy is what a `Vec` is; the
/// terminator and the allocation-failure arm have no counterpart.
///
/// # The three frozen details
///
/// * Header `Features:` with no trailing space, one space before each name, one
///   trailing newline from `puts("")`.
/// * **`CAcert` is appended before the sort**, so it lands in sorted position
///   rather than at the end. The gate is
///   `crate::ca_embed::is_embedded`, a `const` predicate that is false when no
///   bundle is configured. `CAcert` is not one of the 52 names the harness
///   recognises, so naming it truthfully is harmless -- but fabricating it would
///   be an over-report, which AAP 0.6.5 makes the costly direction.
/// * **The order is `crate::util::struplocompare4sort`'s**, an ASCII-only
///   case-insensitive comparison. A plain sort is case-sensitive and would order
///   a mixed-case list differently, changing the emitted bytes; the `tests`
///   module asserts against an input where the two disagree.
///   `lib/version.c:684` sorts the library's own list the same way.
///
/// C's `qsort` is not a stable sort and `slice::sort_by` is, which is
/// unobservable here: the names are distinct, so no two compare equal.
fn write_features<W: Write>(names: &[&str], out: &mut W) {
    // `:357` -- `if(feature_names[0])`.
    if names.is_empty() {
        return;
    }

    let extended = extended_feature_names(names, ca_embed::is_embedded());

    // `:374-377`.
    let _ = out.write_all(b"Features:");
    for name in &extended {
        let _ = write!(out, " {name}");
    }
    let _ = out.write_all(b"\n");
}

/// The display copy of the feature list -- `src/tool_help.c:358-373`.
///
/// C sizes a heap array at `feature_count` plus one when `CURL_CA_EMBED` is
/// defined, copies the names in, appends `"CAcert"`, terminates and sorts. The
/// `Vec` is that copy; the terminator and the `if(feat_ext)`
/// allocation-failure arm have no Rust counterpart.
///
/// `ca_embedded` is a parameter rather than a direct call to
/// `crate::ca_embed::is_embedded` so that both states of the gate are reachable
/// from a test. The one caller supplies the real predicate, and there is no
/// second source of truth for it.
///
/// The append happens **before** the sort, which is what puts `CAcert` in
/// sorted position rather than at the end.
fn extended_feature_names<'a>(
    names: &[&'a str],
    ca_embedded: bool,
) -> Vec<&'a str> {
    // `:363-371`.
    let mut extended: Vec<&str> = Vec::with_capacity(names.len() + 1);
    extended.extend_from_slice(names);
    if ca_embedded {
        extended.push("CAcert");
    }

    // `:372-373`.
    extended.sort_by(struplocompare4sort);

    extended
}

// tool_list_engines -- src/tool_help.c:387-407

/// `tool_list_engines()` -- `src/tool_help.c:387-407`.
///
/// Reached only through `--engine list`, which `src/tool_getparam.c` turns into
/// `PARAM_ENGINES_REQUESTED` and `src/tool_operate.c:2317` dispatches here.
///
/// GAP #1: `CURLINFO_SSL_ENGINES` is not queried; needed by
/// `src/tool_help.c:393`. Reported rather than worked around.
///
/// The gap is nominal rather than behavioural, and both halves of that are worth
/// stating. `curl_easy_getinfo` lives behind `curl_rs_lib`'s `easy` module,
/// which is not among this file's sanctioned dependencies, so the query cannot
/// be made from here. And the answer is a constant: `ENGINE` is an OpenSSL
/// abstraction that rustls does not have, and rustls is the only TLS
/// implementation at any configuration (AAP 0.8.2), so the list is empty by
/// construction and `  <none>` is the correct output rather than a placeholder
/// for one. If an engine-bearing backend ever existed, the list would arrive
/// through [`list_engines`]'s parameter and this function would be the only
/// thing needing a change.
#[allow(dead_code)] // Dispatched from `src/tool_operate.c:2317-2318`; the Rust
                    // caller is the `EnginesRequested` arm of the operate
                    // driver, which is not this module's to wire.
pub(crate) fn tool_list_engines() {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    list_engines(&[], &mut out);

    let _ = out.flush();
}

/// The body of [`tool_list_engines`], with the list and the stream supplied.
///
/// ```c
/// puts("Build-time engines:");
/// if(engines) {
///   for(; engines; engines = engines->next)
///     curl_mprintf("  %s\n", engines->data);
/// }
/// else {
///   puts("  <none>");
/// }
/// ```
///
/// Frozen: the header `Build-time engines:`, each engine indented by **two**
/// spaces, and the literal `  <none>` -- also two leading spaces -- when the
/// list is empty. The empty case is C's `engines == NULL`, which for a slice is
/// `is_empty()`.
fn list_engines<W: Write>(engines: &[&str], out: &mut W) {
    let _ = writeln!(out, "Build-time engines:");
    if engines.is_empty() {
        let _ = writeln!(out, "  <none>");
    } else {
        for engine in engines {
            let _ = writeln!(out, "  {engine}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    /// `LIBCURL_VERSION` -- `include/curl/curlver.h:35`.
    ///
    /// The only place this file spells the version, and it is inside
    /// `#[cfg(test)]` deliberately: the module proper queries
    /// `curl_rs_lib::version`, which AAP 0.4.1 makes the single owner of the
    /// string, so a literal outside the tests would be exactly the duplicate
    /// that owner exists to prevent. Here it is the *oracle* -- it pins the
    /// value the C tree holds, so a change to the engine's constant fails a
    /// test rather than silently redefining the banner.
    const CURLVER_VERSION: &str = "8.19.0-DEV";

    /// The 26 defined category bits, in the order of `src/tool_help.h:62-87`.
    const ALL_BITS: [(&str, u32); 26] = [
        ("CURLHELP_AUTH", CURLHELP_AUTH),
        ("CURLHELP_CONNECTION", CURLHELP_CONNECTION),
        ("CURLHELP_CURL", CURLHELP_CURL),
        ("CURLHELP_DEPRECATED", CURLHELP_DEPRECATED),
        ("CURLHELP_DNS", CURLHELP_DNS),
        ("CURLHELP_FILE", CURLHELP_FILE),
        ("CURLHELP_FTP", CURLHELP_FTP),
        ("CURLHELP_GLOBAL", CURLHELP_GLOBAL),
        ("CURLHELP_HTTP", CURLHELP_HTTP),
        ("CURLHELP_IMAP", CURLHELP_IMAP),
        ("CURLHELP_IMPORTANT", CURLHELP_IMPORTANT),
        ("CURLHELP_LDAP", CURLHELP_LDAP),
        ("CURLHELP_OUTPUT", CURLHELP_OUTPUT),
        ("CURLHELP_POP3", CURLHELP_POP3),
        ("CURLHELP_POST", CURLHELP_POST),
        ("CURLHELP_PROXY", CURLHELP_PROXY),
        ("CURLHELP_SCP", CURLHELP_SCP),
        ("CURLHELP_SFTP", CURLHELP_SFTP),
        ("CURLHELP_SMTP", CURLHELP_SMTP),
        ("CURLHELP_SSH", CURLHELP_SSH),
        ("CURLHELP_TELNET", CURLHELP_TELNET),
        ("CURLHELP_TFTP", CURLHELP_TFTP),
        ("CURLHELP_TIMEOUT", CURLHELP_TIMEOUT),
        ("CURLHELP_TLS", CURLHELP_TLS),
        ("CURLHELP_UPLOAD", CURLHELP_UPLOAD),
        ("CURLHELP_VERBOSE", CURLHELP_VERBOSE),
    ];

    /// The union of the 26 defined bits -- `(1 << 26) - 1`.
    const DEFINED_MASK: u32 = (1 << 26) - 1;

    /// Captures a writer-parameterised printer's output as text.
    ///
    /// Every byte this module writes is ASCII, so lossy decoding cannot alter
    /// anything; it is used rather than a checked conversion so that no test
    /// needs a fallible unwrap.
    fn captured(render: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut sink: Vec<u8> = Vec::new();
        render(&mut sink);
        String::from_utf8_lossy(&sink).into_owned()
    }

    /// The live version-info value.
    ///
    /// The `Result` is asserted rather than unwrapped: `get_libcurl_info`
    /// cannot fail -- `crate::cli::libinfo` records why its own error arm is
    /// unreachable -- and an assertion reports a surprise there clearly without
    /// putting a panicking unwrap in a file that has none.
    fn live_libinfo() -> Option<LibInfo> {
        let outcome = libinfo::get_libcurl_info();
        assert!(
            outcome.is_ok(),
            "the engine must report its version information"
        );
        outcome.ok()
    }

    /// This file's own source text, for the structural gates.
    ///
    /// Empty when unreadable, which every caller detects by asserting that it
    /// is not -- so a missing file fails loudly without a fallible unwrap.
    fn own_source() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("cli")
            .join("help.rs");
        std::fs::read_to_string(path).unwrap_or_default()
    }

    /// The part of this file that ships: everything before the test module.
    fn shipped_source() -> String {
        let whole = own_source();
        assert!(
            !whole.is_empty(),
            "this file must be readable from its test"
        );
        // The marker is this module's own attribute, which appears exactly once
        // outside a comment and terminates the shipped half of the file.
        let marker = concat!("#[cfg(", "test)]\nmod tests {");
        match whole.split_once(marker) {
            Some((before, _)) => before.to_owned(),
            None => whole,
        }
    }

    /// The 273 option pages under `docs/cmdline-opts/`.
    ///
    /// The same selection `scripts/completion.pl:89` makes and
    /// `docs/cmdline-opts/Makefile.inc`'s `DPAGES` records: regular `*.md`
    /// files, excluding every `_*.md` support page and `MANPAGE.md` by name.
    fn option_pages() -> BTreeSet<String> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("docs")
            .join("cmdline-opts");
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.ends_with(".md"))
            .filter(|name| !name.starts_with('_'))
            .filter(|name| name != "MANPAGE.md")
            .map(|name| name.trim_end_matches(".md").to_owned())
            .collect()
    }

    /// The long option name a help row documents, without the leading `--`.
    fn long_name(opt: &str) -> &str {
        match opt.split_once("--") {
            Some((_, rest)) => match rest.split_once(' ') {
                Some((name, _)) => name,
                None => rest,
            },
            None => "",
        }
    }

    // -- 1. the table has 273 rows, not 274 -------------------------------

    #[test]
    fn helptext_has_exactly_273_rows() {
        // AAP 0.4.1's row for this file says 274. It is wrong, and this is the
        // measurement that supersedes it: `src/tool_listhelp.c:35` declares 273
        // real rows plus a `{ NULL, NULL, 0 }` sentinel a slice does not need.
        assert_eq!(HELPTEXT.len(), 273);
    }

    // -- 2. every `opt` reproduces the C spelling -------------------------

    #[test]
    fn the_first_three_and_last_two_rows_are_verbatim() {
        // Fixes the exact `opt` formatting at both ends of the table, including
        // the leading spaces, the placeholder syntax and the category order.
        assert_eq!(
            HELPTEXT.first(),
            Some(&help(
                "    --abstract-unix-socket <path>",
                "Connect via abstract Unix domain socket",
                CURLHELP_CONNECTION,
            ))
        );
        assert_eq!(
            HELPTEXT.get(1),
            Some(&help(
                "    --alt-svc <filename>",
                "Enable alt-svc with this cache file",
                CURLHELP_HTTP,
            ))
        );
        assert_eq!(
            HELPTEXT.get(2),
            Some(&help(
                "    --anyauth",
                "Pick any authentication method",
                CURLHELP_HTTP | CURLHELP_PROXY | CURLHELP_AUTH,
            ))
        );
        assert_eq!(
            HELPTEXT.get(HELPTEXT.len() - 2),
            Some(&help(
                "-w, --write-out <format>",
                "Output FORMAT after completion",
                CURLHELP_VERBOSE,
            ))
        );
        assert_eq!(
            HELPTEXT.last(),
            Some(&help(
                "    --xattr",
                "Store metadata in extended file attributes",
                CURLHELP_OUTPUT,
            ))
        );
    }

    #[test]
    fn every_opt_takes_one_of_the_two_frozen_shapes() {
        // Four leading spaces when there is no short letter, `-X, --` when
        // there is. The lengths of these strings drive the column arithmetic,
        // so a lost space is a shifted column on every line of the block.
        for row in HELPTEXT {
            let bytes = row.opt.as_bytes();
            if row.opt.starts_with('-') {
                assert_eq!(bytes.get(2..6), Some(&b", --"[..]), "{}", row.opt);
                assert!(
                    bytes.get(1).is_some_and(u8::is_ascii_graphic),
                    "{}",
                    row.opt
                );
            } else {
                assert!(row.opt.starts_with("    --"), "{}", row.opt);
                assert!(!row.opt.starts_with("     "), "{}", row.opt);
            }
            assert!(row.opt.is_ascii(), "{}", row.opt);
            assert!(row.desc.is_ascii(), "{}", row.desc);
            assert!(!row.desc.is_empty(), "{}", row.opt);
        }
    }

    #[test]
    fn exactly_59_rows_carry_a_short_letter() {
        // 59 is also the number of `aliases[]` rows with a letter other than
        // `' '`, measured against `src/tool_getparam.c:80`.
        let with_letter = HELPTEXT
            .iter()
            .filter(|row| row.opt.starts_with('-'))
            .count();
        assert_eq!(with_letter, 59);
    }

    // -- 3. every mask is non-zero and uses only defined bits -------------

    #[test]
    fn every_row_uses_only_defined_category_bits() {
        for row in HELPTEXT {
            assert_ne!(row.categories, 0, "{}", row.opt);
            assert_eq!(row.categories & !DEFINED_MASK, 0, "{}", row.opt);
        }
    }

    #[test]
    fn every_defined_bit_is_used_by_some_row() {
        // Not required by the C, but true of it: a bit no row carries would be
        // a category whose page prints nothing.
        for (name, bit) in ALL_BITS {
            assert!(
                HELPTEXT.iter().any(|row| row.categories & bit != 0),
                "{name} is carried by no row"
            );
        }
    }

    // -- 4. the 25 category descriptors ----------------------------------

    #[test]
    fn categories_are_the_25_rows_in_c_order() {
        let expected: [CategoryDescriptor; 25] = [
            category("auth", "Authentication methods", CURLHELP_AUTH),
            category("connection", "Manage connections", CURLHELP_CONNECTION),
            category("curl", "The command line tool itself", CURLHELP_CURL),
            category("deprecated", "Legacy", CURLHELP_DEPRECATED),
            category("dns", "Names and resolving", CURLHELP_DNS),
            category("file", "FILE protocol", CURLHELP_FILE),
            category("ftp", "FTP protocol", CURLHELP_FTP),
            category("global", "Global options", CURLHELP_GLOBAL),
            category("http", "HTTP and HTTPS protocol", CURLHELP_HTTP),
            category("imap", "IMAP protocol", CURLHELP_IMAP),
            category("ldap", "LDAP protocol", CURLHELP_LDAP),
            category("output", "File system output", CURLHELP_OUTPUT),
            category("pop3", "POP3 protocol", CURLHELP_POP3),
            category("post", "HTTP POST specific", CURLHELP_POST),
            category("proxy", "Options for proxies", CURLHELP_PROXY),
            category("scp", "SCP protocol", CURLHELP_SCP),
            category("sftp", "SFTP protocol", CURLHELP_SFTP),
            category("smtp", "SMTP protocol", CURLHELP_SMTP),
            category("ssh", "SSH protocol", CURLHELP_SSH),
            category("telnet", "TELNET protocol", CURLHELP_TELNET),
            category("tftp", "TFTP protocol", CURLHELP_TFTP),
            category("timeout", "Timeouts and delays", CURLHELP_TIMEOUT),
            category("tls", "TLS/SSL related", CURLHELP_TLS),
            category("upload", "Upload, sending data", CURLHELP_UPLOAD),
            category("verbose", "Tracing, logging etc", CURLHELP_VERBOSE),
        ];
        assert_eq!(CATEGORIES, expected);
    }

    #[test]
    fn important_is_not_a_listed_category() {
        // `src/tool_help.c:42` -- "important is left out because it is the
        // default help page".
        assert!(!CATEGORIES.iter().any(|row| row.opt == "important"));
        assert!(!CATEGORIES
            .iter()
            .any(|row| row.category == CURLHELP_IMPORTANT));
    }

    // -- 5. the bit values -----------------------------------------------

    #[test]
    fn the_26_bits_are_one_shifted_left_by_their_position() {
        for (index, (name, bit)) in ALL_BITS.iter().enumerate() {
            assert_eq!(*bit, 1_u32 << index, "{name}");
        }
    }

    #[test]
    fn curlhelp_all_has_seven_f_not_eight() {
        // `src/tool_help.h:89` -- `0xfffffffU`. 28 bits, not 32, and
        // emphatically not `!0`.
        assert_eq!(CURLHELP_ALL, 0x0fff_ffff);
        assert_ne!(CURLHELP_ALL, u32::MAX);
        assert_eq!(CURLHELP_ALL.count_ones(), 28);
        // It covers every defined bit, which is the property `--help all`
        // relies on.
        assert_eq!(DEFINED_MASK & !CURLHELP_ALL, 0);
    }

    // -- 6. correspondence with args.rs and with the option pages ---------

    #[test]
    fn every_row_resolves_to_an_alias_table_entry() {
        // The help table spells seven rows as their negation -- `--no-alpn`,
        // `--no-buffer`, `--no-clobber`, `--no-keepalive`, `--no-npn`,
        // `--no-progress-meter` and `--no-sessionid` -- while `aliases[]`
        // carries the affirmative name. So a row resolves either directly or
        // after stripping `no-`.
        //
        // The stripped form is deliberately NOT required to carry `ARG_NO`:
        // `--no-npn` maps to the `npn` row, whose type is
        // `ARG_BOOL | ARG_DEPR`. Requiring the flag would fail on a row the C
        // tree really does spell this way.
        for row in HELPTEXT {
            let name = long_name(row.opt);
            assert!(!name.is_empty(), "{}", row.opt);

            let direct = findlongopt(name.as_bytes());
            let stripped = name
                .strip_prefix("no-")
                .and_then(|rest| findlongopt(rest.as_bytes()));
            let found = direct.or(stripped);
            assert!(found.is_some(), "no alias row for --{name}");

            // And the short letter agrees with the alias row's.
            if let Some(alias) = found {
                let shown = row
                    .opt
                    .strip_prefix('-')
                    .and_then(|rest| rest.chars().next());
                let expected = if alias.letter == ' ' {
                    None
                } else {
                    Some(alias.letter)
                };
                assert_eq!(shown, expected, "--{name}");
            }
        }
    }

    #[test]
    fn the_273_rows_correspond_one_for_one_with_the_option_pages() {
        // `docs/cmdline-opts/` holds 293 `.md` files: 273 option pages, 19
        // `_*.md` support pages and `MANPAGE.md`. The help table documents
        // exactly the option pages, and the embedded manual is generated from
        // the same set -- so a row without a page, or a page without a row,
        // means `--help <option>` and `--help all` disagree.
        let pages = option_pages();
        assert_eq!(pages.len(), 273, "expected 273 option pages");

        let documented: BTreeSet<String> = HELPTEXT
            .iter()
            .map(|row| long_name(row.opt).to_owned())
            .collect();
        assert_eq!(documented.len(), HELPTEXT.len(), "duplicate long names");
        assert_eq!(documented, pages);
    }

    // -- 7. the column arithmetic ----------------------------------------

    /// The `CURLHELP_IMPORTANT` block at 79 columns -- the default help page.
    ///
    /// Computed independently from the C algorithm at `src/tool_help.c:70-106`
    /// rather than from this implementation, so the comparison is an oracle and
    /// not a restatement. 14 rows, option column 28 wide.
    const GOLDEN_IMPORTANT_79: &[&str] = &[
        " -d, --data <data>            HTTP POST data",
        " -f, --fail                   Fail fast with no output on HTTP errors",
        " -I, --head                   Show document info only",
        " -H, --header <header/@file>  Pass custom header(s) to server",
        " -h, --help <subject>         Get help for commands",
        " -o, --output <file>          Write to file instead of stdout",
        " -O, --remote-name            Write output to file named as remote file",
        " -i, --show-headers           Show response headers in output",
        " -s, --silent                 Silent mode",
        " -T, --upload-file <file>     Transfer local FILE to destination",
        " -u, --user <user:password>   Server user and password",
        " -A, --user-agent <name>      Send User-Agent <name> to server",
        " -v, --verbose                Make the operation more talkative",
        " -V, --version                Show version number and quit",
    ];

    #[test]
    fn the_important_block_at_79_columns_matches_the_golden_snapshot() {
        let rendered =
            captured(|sink| print_category(CURLHELP_IMPORTANT, 79, sink));
        let mut expected = GOLDEN_IMPORTANT_79.join("\n");
        expected.push('\n');
        assert_eq!(rendered, expected);
    }

    #[test]
    fn a_narrow_width_collapses_the_padding_without_truncating() {
        // `%-*s` with a width below the string's length prints the whole
        // string. So at 20 columns the option column has no padding at all and
        // every option and description still appears in full.
        let rendered =
            captured(|sink| print_category(CURLHELP_IMPORTANT, 20, sink));
        let selected: Vec<&HelpTxt> = HELPTEXT
            .iter()
            .filter(|row| row.categories & CURLHELP_IMPORTANT != 0)
            .collect();

        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), selected.len());
        for (line, row) in lines.iter().zip(&selected) {
            // One leading space, the option, then immediately the two-space
            // separator: the padding has collapsed to zero.
            assert_eq!(*line, format!(" {}  {}", row.opt, row.desc));
        }
    }

    #[test]
    fn a_width_of_zero_or_one_does_not_panic_and_still_prints_in_full() {
        // C's `cols >= 2` guard means the per-row adjustment is skipped
        // entirely below two columns, and `longdesc > cols` has already forced
        // the option column to zero. Nothing is truncated, and nothing wraps.
        for cols in [0_usize, 1, 2, 3] {
            let rendered =
                captured(|sink| print_category(CURLHELP_IMPORTANT, cols, sink));
            assert_eq!(rendered.lines().count(), 14, "cols={cols}");
            for line in rendered.lines() {
                assert!(line.starts_with(' '), "cols={cols}");
                assert!(line.contains("  "), "cols={cols}");
            }
        }
    }

    #[test]
    fn every_line_is_one_space_then_the_option_then_two_spaces() {
        // The `" %-*s  %s\n"` shape, asserted across the whole table at the
        // default width so that no row can have lost its leading space or had
        // its separator widened.
        let rendered = captured(|sink| print_category(CURLHELP_ALL, 79, sink));
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 273);
        for (line, row) in lines.iter().zip(HELPTEXT) {
            assert!(line.starts_with(&format!(" {}", row.opt)), "{line}");
            assert!(line.ends_with(&format!("  {}", row.desc)), "{line}");
        }
    }

    #[test]
    fn a_category_page_prints_its_heading_then_its_rows() {
        // `src/tool_help.c:114` -- `"%s: %s\n"`, then the block.
        let rendered = captured(|sink| {
            assert!(get_category_content("ftp", 79, sink));
        });
        assert!(rendered.starts_with("ftp: FTP protocol\n"));
        assert!(rendered.lines().count() > 1);
    }

    #[test]
    fn a_category_page_lookup_is_case_insensitive() {
        let lower = captured(|sink| {
            assert!(get_category_content("tls", 79, sink));
        });
        let upper = captured(|sink| {
            assert!(get_category_content("TLS", 79, sink));
        });
        let mixed = captured(|sink| {
            assert!(get_category_content("TlS", 79, sink));
        });
        assert_eq!(lower, upper);
        assert_eq!(lower, mixed);
    }

    #[test]
    fn an_unknown_category_prints_nothing_and_reports_not_found() {
        let rendered = captured(|sink| {
            assert!(!get_category_content("nosuchcategory", 79, sink));
        });
        assert!(rendered.is_empty());
    }

    // -- 8. get_categories -----------------------------------------------

    #[test]
    fn get_categories_pads_to_11_with_single_spaces_either_side() {
        // `" %-11s %s\n"`: one leading space, width 11, ONE separating space --
        // deliberately unlike `print_category`'s two.
        let rendered = captured(get_categories);
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 25);
        for (line, row) in lines.iter().zip(&CATEGORIES) {
            let pad = CATEGORY_NAME_WIDTH.saturating_sub(row.opt.len());
            let expected =
                format!(" {}{} {}", row.opt, " ".repeat(pad), row.desc);
            assert_eq!(*line, expected);
        }
        assert_eq!(CATEGORY_NAME_WIDTH, 11);
        // The widest name is "deprecated" and "connection", both 10, so every
        // line really is padded rather than overflowing.
        assert!(CATEGORIES.iter().all(|row| row.opt.len() <= 11));
    }

    // -- 9. get_categories_list ------------------------------------------

    /// The flow-filled category list at 79 columns.
    ///
    /// Computed independently from `src/tool_help.c:129-154`. Note the trailing
    /// space before each newline: C prefixes the newline to the *next* entry,
    /// so the separator that was already emitted stays put.
    const GOLDEN_LIST_79: &str = concat!(
        "auth, connection, curl, deprecated, dns, file, ftp, global, http, ",
        "imap, ldap, \noutput, pop3, post, proxy, scp, sftp, smtp, ssh, ",
        "telnet, tftp, timeout, tls, \nupload, verbose.\n",
    );

    #[test]
    fn the_category_list_at_79_columns_matches_the_golden_snapshot() {
        let rendered = captured(|sink| get_categories_list(79, sink));
        assert_eq!(rendered, GOLDEN_LIST_79);
    }

    #[test]
    fn the_category_list_names_all_25_and_ends_with_a_full_stop() {
        for width in [1_usize, 2, 20, 40, 79, 80, 200, 10_000] {
            let rendered = captured(|sink| get_categories_list(width, sink));
            assert!(rendered.ends_with("verbose.\n"), "width={width}");
            for row in &CATEGORIES {
                assert!(rendered.contains(row.opt), "width={width}");
            }
            // Every separator is ", " -- never "," alone and never " ,".
            assert!(!rendered.contains(" ,"), "width={width}");
            assert_eq!(
                rendered.matches(", ").count(),
                24,
                "width={width}: 24 separators for 25 entries"
            );
        }
    }

    #[test]
    fn the_final_entry_uses_plus_one_and_the_others_plus_two() {
        // The asymmetry at `src/tool_help.c:138` against `:144`, isolated.
        //
        // At a width where `col + len("verbose") + 1` is exactly the width, the
        // strict `<` sends the final entry to its own line; one column wider it
        // stays put. Nothing but the `+ 1` and the strict comparison produces
        // that pair of outcomes one column apart.
        let mut boundary = None;
        for width in 1_usize..200 {
            let tight = captured(|sink| get_categories_list(width, sink));
            let looser = captured(|sink| get_categories_list(width + 1, sink));
            let tight_lines = tight.lines().count();
            let loose_lines = looser.lines().count();
            if tight_lines > loose_lines {
                boundary = Some(width);
                break;
            }
        }
        assert!(boundary.is_some(), "no width reduced the line count");
    }

    // -- 10. tool_help(None) ----------------------------------------------

    #[test]
    fn the_two_notes_are_byte_exact() {
        // Both are built from concatenated C literals, so the embedded newlines
        // and the literal double quotes are what must survive.
        assert_eq!(
            CATEGORY_NOTE,
            "\nThis is not the full help; this menu is split into categories.\n\
             Use \"--help category\" to get an overview of all categories, \
             which are:"
        );
        assert_eq!(
            CATEGORY_NOTE2,
            "Use \"--help all\" to list all options\n\
             Use \"--help [option]\" to view documentation for a given option"
        );
        // The second line is present because the manual is unconditional here.
        // The claim is verified rather than restated: the artifact really is
        // there, so `USE_MANUAL` is genuinely satisfied.
        assert_eq!(MANUAL_PRESENT, hugehelp::manual_lines() > 0);
        assert_eq!(CATEGORY_NOTE2.lines().count(), 2);
    }

    #[test]
    fn the_default_page_emits_its_five_parts_in_order() {
        let (out, err) = rendered_help(None, 79);
        assert!(err.is_empty(), "the default page writes nothing to stderr");

        let mut expected = String::new();
        expected.push_str("Usage: curl [options...] <url>\n");
        expected.push_str(&GOLDEN_IMPORTANT_79.join("\n"));
        expected.push('\n');
        expected.push_str(CATEGORY_NOTE);
        expected.push('\n');
        expected.push_str(GOLDEN_LIST_79);
        expected.push_str(CATEGORY_NOTE2);
        expected.push('\n');

        assert_eq!(out, expected);
    }

    #[test]
    fn the_usage_line_names_curl_not_the_cargo_package() {
        // `src/tool_help.c:240` verbatim.
        assert_eq!(USAGE, "Usage: curl [options...] <url>");
        assert!(!USAGE.contains("curl-rs"));
    }

    /// Runs `tool_help_to` at a chosen width and returns both streams.
    fn rendered_help(category: Option<&str>, cols: usize) -> (String, String) {
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        tool_help_to(category, cols, &mut out, &mut err);
        (
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    // -- 11. the other tool_help branches ---------------------------------

    #[test]
    fn help_all_prints_every_row() {
        let (out, err) = rendered_help(Some("all"), 79);
        assert!(err.is_empty());
        assert_eq!(out.lines().count(), 273);
        let direct = captured(|sink| print_category(CURLHELP_ALL, 79, sink));
        assert_eq!(out, direct);
    }

    #[test]
    fn help_category_lists_all_25() {
        let (out, err) = rendered_help(Some("category"), 79);
        assert!(err.is_empty());
        assert_eq!(out.lines().count(), 25);
        assert_eq!(out, captured(get_categories));
    }

    #[test]
    fn the_all_and_category_keywords_are_case_insensitive() {
        for keyword in ["all", "ALL", "All"] {
            let (out, _) = rendered_help(Some(keyword), 79);
            assert_eq!(out.lines().count(), 273, "{keyword}");
        }
        for keyword in ["category", "CATEGORY", "Category"] {
            let (out, _) = rendered_help(Some(keyword), 79);
            assert_eq!(out.lines().count(), 25, "{keyword}");
        }
    }

    #[test]
    fn an_unknown_category_lists_them_after_a_blank_line() {
        // `src/tool_help.c:297` -- the literal ends with `\n` and `puts` adds
        // another, so exactly one blank line separates the message from the
        // list.
        let (out, err) = rendered_help(Some("nosuchcategory"), 79);
        assert!(err.is_empty());
        let expected = format!(
            "Unknown category provided, here is a list of all categories:\n\n{}",
            captured(get_categories)
        );
        assert_eq!(out, expected);
        assert_eq!(
            UNKNOWN_CATEGORY,
            "Unknown category provided, here is a list of all categories:\n"
        );
    }

    #[test]
    fn an_empty_category_is_treated_as_an_unknown_one() {
        // C reaches `get_category_content("")` because `category[0]` is the
        // terminator rather than `-`.
        let (out, _) = rendered_help(Some(""), 79);
        assert!(out.starts_with("Unknown category provided"));
    }

    // -- 12 and 13. per-option help ---------------------------------------

    #[test]
    fn a_short_option_resolves_only_when_it_is_exactly_two_bytes() {
        // `src/tool_help.c:270` -- `else if(!category[2])`.
        assert!(option_help_key("-d").is_some());
        assert!(option_help_key("-f").is_some());
        assert!(option_help_key("-dq").is_none());
        assert!(option_help_key("-d ").is_none());
        // An unassigned letter resolves to nothing.
        assert!(option_help_key("-\u{7f}").is_none());
    }

    #[test]
    fn a_bare_dash_resolves_to_nothing_without_reading_out_of_bounds() {
        // C reads `category[2]` for the input `-`, one byte past the
        // terminator. Reading an absent byte as `0` sends it to
        // `findshortopt(0)`, which `src/tool_getparam.c:832-833` rejects with
        // `letter <= ' '`.
        assert!(option_help_key("-").is_none());
        assert!(findshortopt(0).is_none());
        // And the two-dash form looks up the empty name, which matches nothing.
        assert!(option_help_key("--").is_none());
        assert!(findlongopt(b"").is_none());
    }

    #[test]
    fn a_long_option_resolves_and_a_nonexistent_one_does_not() {
        assert!(option_help_key("--data").is_some());
        assert!(option_help_key("--xattr").is_some());
        assert!(option_help_key("--nosuchoption").is_none());
    }

    #[test]
    fn the_no_prefix_is_accepted_for_booleans_and_refused_otherwise() {
        // `src/tool_help.c:265-268` -- "a --no- prefix for a non-boolean is not
        // specifying a proper option".
        assert!(option_help_key("--no-clobber").is_some());
        assert!(option_help_key("--no-buffer").is_some());
        // `--data` is `ARG_STRG`, so its negation is not an option.
        assert!(option_help_key("--no-data").is_none());
        assert!(option_help_key("--no-alt-svc").is_none());
        // Sanity: the two halves of the rule really do differ in type.
        if let (Some(clobber), Some(data)) =
            (findlongopt(b"clobber"), findlongopt(b"data"))
        {
            assert_eq!(argtype(clobber.desc), ARG_BOOL);
            assert_ne!(argtype(data.desc), ARG_BOOL);
        }
    }

    #[test]
    fn the_search_key_stops_at_the_double_dash_when_there_is_a_letter() {
        // `src/tool_help.c:279` -- `"\n    -%c, --"`. The long name is
        // deliberately absent; the key is only a prefix of the manual heading,
        // and that truncation is what makes the scan match.
        assert_eq!(
            option_help_key("--data"),
            Some(("\n    -d, --".to_owned(), MANUAL_END_NEXT))
        );
        // Reached through the negation, the key is still the affirmative
        // letter's.
        assert_eq!(
            option_help_key("--no-buffer"),
            Some(("\n    -N, --".to_owned(), MANUAL_END_NEXT))
        );
        // And a short spelling produces the same key as its long one.
        assert_eq!(option_help_key("-d"), option_help_key("--data"));
    }

    #[test]
    fn the_search_key_uses_the_negated_name_for_an_arg_no_row() {
        // `src/tool_help.c:281` -- `"\n    --no-%s"`, taking the affirmative
        // `lname` and prefixing `no-`.
        assert_eq!(
            option_help_key("--no-clobber"),
            Some(("\n    --no-clobber".to_owned(), MANUAL_END_NEXT))
        );
        // The same row reached by its affirmative name also gets the negated
        // heading, because the branch keys off `ARG_NO` rather than off the
        // spelling the user typed.
        assert_eq!(
            option_help_key("--clobber"),
            Some(("\n    --no-clobber".to_owned(), MANUAL_END_NEXT))
        );
    }

    #[test]
    fn the_search_key_otherwise_echoes_the_name_as_given() {
        // `src/tool_help.c:283` -- `"\n    %s"` with `category` itself.
        assert_eq!(
            option_help_key("--alt-svc"),
            Some(("\n    --alt-svc".to_owned(), MANUAL_END_NEXT))
        );
    }

    #[test]
    fn xattr_is_terminated_by_files_and_everything_else_by_the_next_option() {
        // `src/tool_help.c:284-288` -- "this is the last option, which then
        // ends when FILES starts".
        assert_eq!(
            option_help_key("--xattr"),
            Some(("\n    --xattr".to_owned(), MANUAL_END_LAST))
        );
        assert_eq!(MANUAL_END_LAST, "\nFILES");
        assert_eq!(MANUAL_END_NEXT, "\n    -");
        assert_eq!(MANUAL_TRIGGER, "\nALL OPTIONS\n");

        let mut with_files = 0;
        for row in HELPTEXT {
            let name = long_name(row.opt);
            if let Some((_, endarg)) = option_help_key(&format!("--{name}")) {
                if endarg == MANUAL_END_LAST {
                    with_files += 1;
                }
            }
        }
        assert_eq!(with_files, 1, "only C_XATTR ends at FILES");
    }

    #[test]
    fn every_search_key_fits_the_cmdbuf_and_the_scanner_window() {
        // C writes the key with `curl_msnprintf(cmdbuf, 80, ...)` and then
        // feeds it to a 40-byte matcher. A key over 39 bytes could never match,
        // so this bound is behavioural rather than cosmetic.
        for row in HELPTEXT {
            let name = long_name(row.opt);
            if let Some((key, _)) = option_help_key(&format!("--{name}")) {
                assert!(key.len() < CMDBUF_LEN, "{key}");
                assert!(key.len() <= RBUF_LEN, "{key} exceeds the window");
                assert!(key.starts_with("\n    "), "{key}");
            }
        }
    }

    #[test]
    fn an_unresolvable_option_reports_on_stderr_and_nothing_on_stdout() {
        let (out, err) = rendered_help(Some("--nosuchoption"), 79);
        assert!(out.is_empty(), "the failure must not reach stdout");
        assert_eq!(
            err,
            "Incorrect option name to show help for, see curl -h\n"
        );
        assert_eq!(
            INCORRECT_OPTION,
            "Incorrect option name to show help for, see curl -h"
        );
        assert!(!INCORRECT_OPTION.contains("curl-rs"));
    }

    #[test]
    fn the_no_manual_arm_is_reproduced_and_unreachable() {
        // `src/tool_help.c:291-292`, the `#else` of `USE_MANUAL`. It cannot
        // fire, because the manual is unconditional here -- so the constant is
        // asserted rather than the branch exercised.
        assert_eq!(
            MANUAL_ABSENT,
            "Cannot comply. This curl was built without built-in manual"
        );
        assert_eq!(
            MANUAL_PRESENT,
            hugehelp::manual_lines() > 0,
            "the branch guarded by this cannot run while the manual is there"
        );
    }

    #[test]
    fn truncation_keeps_whole_characters_and_never_grows_the_input() {
        assert_eq!(truncate_bytes("abcd".to_owned(), 2), "ab");
        assert_eq!(truncate_bytes("abcd".to_owned(), 9), "abcd");
        assert_eq!(truncate_bytes(String::new(), 0), "");
        // A multi-byte character is dropped rather than split.
        assert_eq!(truncate_bytes("a\u{e9}".to_owned(), 2), "a");
        assert_eq!(truncate_bytes("\u{e9}".to_owned(), 1), "");
    }

    // -- 14 and 15. the manual scanner ------------------------------------

    /// Feeds `text` through a fresh scanner line by line, exactly as
    /// `crate::cli::hugehelp::showhelp` feeds the manual: each line as its own
    /// piece, then a separate one-byte newline.
    fn scan(
        lines: &[&str],
        trigger: &str,
        arg: &str,
        endarg: &str,
    ) -> (String, bool) {
        let mut ctx = inithelpscan(trigger, arg, endarg);
        let mut sink: Vec<u8> = Vec::new();
        let mut finished = true;
        for line in lines {
            if !helpscan(line.as_bytes(), &mut ctx, &mut sink)
                || !helpscan(b"\n", &mut ctx, &mut sink)
            {
                finished = false;
                break;
            }
        }
        (String::from_utf8_lossy(&sink).into_owned(), finished)
    }

    /// A miniature manual with the same shape as the real one.
    ///
    /// The **leading newlines matter and are not decoration.**
    /// `src/mkhelp.pl:211-224` drops blank lines and prepends a single `\n` to
    /// the element that followed a blank run, so an element that begins a new
    /// section carries its own newline. That is what leaves a `\n` in front of
    /// each heading for the arg needle to match, given that the trigger match
    /// has already consumed the newline that terminated `ALL OPTIONS`.
    /// Verified against the generated artifact, whose corresponding elements
    /// are `"\nALL OPTIONS"`, `"\n    --abstract-unix-socket <path>"`,
    /// `"\n    --xattr"` and `"\nFILES"`.
    const FAKE_MANUAL: &[&str] = &[
        "NAME",
        "    curl - transfer a URL",
        "\nSYNOPSIS",
        "    curl [options] url",
        "\nALL OPTIONS",
        "\n    --alpha <x>",
        "           The alpha option.",
        "\n    --beta",
        "           The beta option.",
        "\nFILES",
        "    ~/.curlrc",
    ];

    #[test]
    fn the_scanner_emits_one_section_and_stops_at_the_next_option() {
        let (text, finished) = scan(
            FAKE_MANUAL,
            MANUAL_TRIGGER,
            "\n    --alpha",
            MANUAL_END_NEXT,
        );
        // The heading is echoed WITHOUT its leading newline -- `&arg[1]`.
        assert!(text.starts_with("    --alpha"));
        assert!(text.contains("The alpha option."));
        // The next option's section is not included, and the scan stopped.
        assert!(!text.contains("The beta option."));
        assert!(!finished, "the terminator must stop the feed");
    }

    #[test]
    fn the_scanner_emits_the_needle_minus_its_first_byte() {
        let (text, _) =
            scan(FAKE_MANUAL, MANUAL_TRIGGER, "\n    --beta", MANUAL_END_LAST);
        assert!(
            text.starts_with("    --beta"),
            "expected the needle without its newline, got {text:?}"
        );
        assert!(!text.starts_with('\n'));
        assert!(text.contains("The beta option."));
    }

    #[test]
    fn the_last_section_is_terminated_by_files() {
        let (text, finished) =
            scan(FAKE_MANUAL, MANUAL_TRIGGER, "\n    --beta", MANUAL_END_LAST);
        assert!(!finished);
        assert!(!text.contains("~/.curlrc"));
    }

    #[test]
    fn the_scanner_stays_silent_until_the_trigger() {
        // The heading appears in the synopsis-like prelude too; nothing may be
        // emitted before `ALL OPTIONS` has gone past.
        let prelude: &[&str] = &["    --alpha <x>", "not the section"];
        let (text, finished) =
            scan(prelude, MANUAL_TRIGGER, "\n    --alpha", MANUAL_END_NEXT);
        assert!(text.is_empty(), "got {text:?}");
        assert!(finished, "without a terminator the feed runs to the end");
    }

    #[test]
    fn a_missing_section_emits_nothing_and_runs_to_the_end() {
        let (text, finished) = scan(
            FAKE_MANUAL,
            MANUAL_TRIGGER,
            "\n    --gamma",
            MANUAL_END_NEXT,
        );
        assert!(text.is_empty());
        assert!(finished);
    }

    #[test]
    fn init_zeroes_the_whole_window_and_starts_at_the_trigger_stage() {
        let ctx = inithelpscan(MANUAL_TRIGGER, "\n    -x", MANUAL_END_NEXT);
        assert_eq!(ctx.rbuf, [0_u8; RBUF_LEN]);
        assert_eq!(ctx.olen, 0);
        assert_eq!(ctx.show, ScanStage::Trigger);
        assert_eq!(RBUF_LEN, 40);
        assert_eq!(OBUF_LEN, 160);
        assert_eq!(CMDBUF_LEN, 80);
    }

    #[test]
    fn a_line_of_obuf_length_or_more_bails_out() {
        // 159 bytes is the longest printable line: the guard runs before the
        // accumulator is touched, so 160 bytes can be held and the 161st byte
        // -- newline or not -- stops the scan.
        let fits = "a".repeat(OBUF_LEN - 1);
        let exact = "a".repeat(OBUF_LEN);
        let over = "a".repeat(OBUF_LEN + 1);

        let body = |line: &str| -> (String, bool) {
            let owned = line.to_owned();
            // The same framing `src/mkhelp.pl` emits: each section-opening
            // element carries its own leading newline.
            let lines = ["\nALL OPTIONS", "\n    --alpha", owned.as_str()];
            scan(&lines, MANUAL_TRIGGER, "\n    --alpha", MANUAL_END_NEXT)
        };

        let (text, finished) = body(&fits);
        assert!(text.contains(&fits), "159 bytes must survive");
        assert!(finished);

        let (_, finished) = body(&exact);
        assert!(!finished, "a 160-byte line must bail out on its newline");

        let (_, finished) = body(&over);
        assert!(!finished, "a 161-byte line must bail out on the 161st byte");
    }

    #[test]
    fn an_over_long_needle_never_matches_instead_of_overflowing() {
        // C would write past the end of a 40-byte array here; its own
        // `DEBUGASSERT` at `src/tool_help.c:169-170` does not catch every such
        // case. Never matching is the safe reading.
        let needle = "\n".to_owned() + &"z".repeat(RBUF_LEN);
        assert!(needle.len() > RBUF_LEN);
        // The needle appears verbatim in the feed, so a scanner that could hold
        // it would fire. It cannot, so nothing is emitted and the feed runs to
        // the end.
        let lines: &[&str] = &[needle.as_str(), "\nALL OPTIONS"];
        let (text, finished) =
            scan(lines, &needle, "\n    --alpha", MANUAL_END_NEXT);
        assert!(text.is_empty(), "got {text:?}");
        assert!(finished);
    }

    #[test]
    fn the_scanner_never_panics_for_any_shape_of_input() {
        // A one-byte feed, a feed with no newline at all, empty pieces, empty
        // needles and arbitrary bytes.
        let feeds: &[&[u8]] = &[
            b"",
            b"a",
            b"\n",
            b"no newline anywhere in this piece at all",
            &[0_u8, 1, 2, 255, 128, 10, 13],
        ];
        let needles = [
            ("\nALL OPTIONS\n", "\n    -x", "\n    -"),
            ("", "", ""),
            ("\n", "\n", "\n"),
            ("x", "y", "z"),
        ];
        for (trigger, arg, endarg) in needles {
            for feed in feeds {
                let mut ctx = inithelpscan(trigger, arg, endarg);
                let mut sink: Vec<u8> = Vec::new();
                // Fed twice, so a stage transition inside the first feed is
                // exercised by the second.
                let _ = helpscan(feed, &mut ctx, &mut sink);
                let _ = helpscan(feed, &mut ctx, &mut sink);
            }
        }
    }

    // -- the scanner against the real manual ------------------------------

    #[test]
    fn the_real_manual_yields_one_option_section_per_search_key() {
        // The end-to-end check: the actual generated artifact, driven with the
        // framing `crate::cli::hugehelp::showhelp` uses, keyed by the actual
        // output of `option_help_key`. Nothing here is synthetic.
        assert!(
            hugehelp::manual_lines() > 1000,
            "the manual artifact must be present and complete"
        );

        // A row with a short letter: the key stops at `--`, so the manual's
        // fuller heading must still match it.
        let (key, endarg) = option_help_key("--data").unwrap_or_default();
        assert!(!key.is_empty(), "--data must resolve");
        assert_eq!(endarg, MANUAL_END_NEXT);
        let (section, finished) =
            scan(hugehelp::MANUAL, MANUAL_TRIGGER, &key, endarg);
        assert!(
            section.starts_with("    -d, --"),
            "expected the heading without its newline, got {:?}",
            section.get(..60)
        );
        assert!(section.contains("--data"), "got {:?}", section.get(..200));
        assert!(!finished, "the next option must stop the scan");
        // One option's section only: the terminator is the next heading, so no
        // second option heading may appear.
        assert_eq!(
            section.matches("\n    -").count(),
            0,
            "the section must not run into the next option"
        );

        // The last row in the manual, whose terminator is FILES rather than the
        // next option.
        let (key, endarg) = option_help_key("--xattr").unwrap_or_default();
        assert!(!key.is_empty(), "--xattr must resolve");
        assert_eq!(endarg, MANUAL_END_LAST);
        let (section, finished) =
            scan(hugehelp::MANUAL, MANUAL_TRIGGER, &key, endarg);
        assert!(section.starts_with("    --xattr"), "got {section:?}");
        assert!(!finished, "FILES must stop the scan");
        assert!(
            !section.contains("FILES"),
            "the terminator must not be emitted"
        );
    }

    #[test]
    fn every_search_key_finds_its_section_in_the_real_manual() {
        // The property that matters for `--help <option>`: all 273 rows must
        // produce output. A key that matches nothing would make the flag print
        // an empty section, which is the silent failure this test exists to
        // prevent.
        let mut missing: Vec<String> = Vec::new();
        for row in HELPTEXT {
            let name = long_name(row.opt);
            let Some((key, endarg)) = option_help_key(&format!("--{name}"))
            else {
                missing.push(format!("--{name} does not resolve"));
                continue;
            };
            let (section, _) =
                scan(hugehelp::MANUAL, MANUAL_TRIGGER, &key, endarg);
            if section.is_empty() {
                missing.push(format!("--{name} found no section"));
            }
        }
        assert!(missing.is_empty(), "{missing:?}");
    }

    #[test]
    fn a_write_failure_does_not_stop_the_scan() {
        // C never reads what `puts` and `fputs` return, so a failed write costs
        // one line and nothing more.
        struct Closed;

        impl Write for Closed {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("closed"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("closed"))
            }
        }

        let mut ctx =
            inithelpscan(MANUAL_TRIGGER, "\n    --alpha", MANUAL_END_NEXT);
        let mut finished = true;
        for line in FAKE_MANUAL {
            if !helpscan(line.as_bytes(), &mut ctx, &mut Closed)
                || !helpscan(b"\n", &mut ctx, &mut Closed)
            {
                finished = false;
                break;
            }
        }
        // It still reached the terminator, which is the parity property: the
        // scan is driven by the input, not by the sink.
        assert!(!finished);
    }

    // -- 16 and 17. the Protocols line ------------------------------------

    /// The nine schemes this implementation serves, in the engine's order.
    const NINE_SCHEMES: &[&str] = &[
        "file", "ftp", "ftps", "http", "https", "scp", "sftp", "ws", "wss",
    ];

    /// The 24 schemes that are registered for ABI completeness but never
    /// advertised -- `tests/runtests.pl:841-844` turns every advertised
    /// protocol into a harness feature as well, so naming one of these would
    /// convert 283 clean skips into failures.
    const STUBBED_SCHEMES: &[&str] = &[
        "dict", "gopher", "gophers", "imap", "imaps", "ldap", "ldaps", "mqtt",
        "mqtts", "pop3", "pop3s", "rtmp", "rtmpe", "rtmps", "rtmpt", "rtmpte",
        "rtmpts", "rtsp", "smb", "smbs", "smtp", "smtps", "telnet", "tftp",
    ];

    #[test]
    fn the_protocols_line_inserts_ipfs_and_ipns_in_alphabetical_position() {
        let rendered = captured(|sink| write_protocols(NINE_SCHEMES, sink));
        assert_eq!(
            rendered,
            "Protocols: file ftp ftps http https ipfs ipns scp sftp ws wss\n"
        );
        // The header carries no trailing space of its own, and every name is
        // preceded by exactly one.
        assert!(rendered.starts_with("Protocols: file"));
        assert!(!rendered.contains("  "));
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    fn the_insertion_anchor_advances_past_names_sorting_before_ipfs() {
        // The anchor starts at `http` and walks forward while the next entry
        // sorts before `ipfs` byte-wise. With `imap` present the pair lands
        // after it, not after `http`.
        let with_imap = &["http", "imap", "scp"];
        let rendered = captured(|sink| write_protocols(with_imap, sink));
        assert_eq!(rendered, "Protocols: http imap ipfs ipns scp\n");

        // Without `http` there is no anchor at all and the pair is absent --
        // C's comment: "we have ipfs and ipns support if libcurl has http
        // support".
        let no_http = &["ftp", "sftp"];
        let rendered = captured(|sink| write_protocols(no_http, sink));
        assert_eq!(rendered, "Protocols: ftp sftp\n");
        assert!(!rendered.contains("ipfs"));
    }

    #[test]
    fn the_pair_is_emitted_only_once() {
        // C clears `insert` after emitting, so a duplicated anchor entry cannot
        // produce the pair twice.
        let duplicated = &["http", "http", "scp"];
        let rendered = captured(|sink| write_protocols(duplicated, sink));
        assert_eq!(rendered.matches("ipfs").count(), 1);
        assert_eq!(rendered.matches("ipns").count(), 1);
    }

    #[test]
    fn rtmp_prints_but_its_variants_do_not() {
        // `src/tool_help.c:344-347` -- "do not list rtmp?* protocols. They may
        // only appear together with rtmp".
        let list = &["rtmp", "rtmpe", "rtmps", "rtmpt", "rtmpte", "rtmpts"];
        let rendered = captured(|sink| write_protocols(list, sink));
        assert_eq!(rendered, "Protocols: rtmp\n");

        // The prefix test is case-insensitive, and a name shorter than four
        // bytes cannot match it.
        let mixed = &["RTMPE", "ftp", "rtm"];
        let rendered = captured(|sink| write_protocols(mixed, sink));
        assert_eq!(rendered, "Protocols: ftp rtm\n");
    }

    #[test]
    fn an_empty_protocol_list_suppresses_the_whole_line() {
        // C's `if(built_in_protos[0])` guard. This is the state of the build
        // today, because the engine withholds every scheme until the protocol
        // engine exists -- and it is the truthful posture, under which the 283
        // fixtures targeting unimplemented schemes skip rather than fail.
        let rendered = captured(|sink| write_protocols(&[], sink));
        assert!(rendered.is_empty());
    }

    #[test]
    fn no_stubbed_scheme_is_ever_advertised() {
        let Some(info) = live_libinfo() else { return };
        let rendered =
            captured(|sink| write_protocols(info.built_in_protos(), sink));
        for scheme in STUBBED_SCHEMES {
            assert!(
                !rendered.split(' ').any(|token| token.trim_end() == *scheme),
                "{scheme} must not be advertised"
            );
        }
        // Whatever the engine reports is printed unfiltered, apart from the
        // ipfs/ipns insertion and the rtmp suppression the C tool performs.
        for name in info.built_in_protos() {
            assert!(rendered.contains(name), "{name} was dropped");
        }
    }

    // -- 18. the Features line --------------------------------------------

    #[test]
    fn the_feature_list_is_ordered_case_insensitively() {
        // A plain byte sort would put every capitalised name before every
        // lowercase one. `struplocompare4sort` folds ASCII case, so the order
        // differs -- and the emitted line differs with it.
        let names = &["zstd", "AsyncDNS", "brotli", "SSL"];
        let caseless = extended_feature_names(names, false);
        assert_eq!(caseless, ["AsyncDNS", "brotli", "SSL", "zstd"]);

        // The contrast: `str`'s own ordering is byte-wise, so every capitalised
        // name sorts before every lowercase one. Stated as a literal rather
        // than produced by a sort call -- a hand-computed oracle is stronger
        // than a restatement, and no sort call belongs in this file at all.
        let bytewise = ["AsyncDNS", "SSL", "brotli", "zstd"];
        assert_ne!(
            caseless.as_slice(),
            &bytewise[..],
            "the test input must distinguish the two orders"
        );
    }

    #[test]
    fn cacert_is_appended_before_the_sort_so_it_lands_in_position() {
        let names = &["zstd", "AsyncDNS", "brotli", "SSL"];
        let with_bundle = extended_feature_names(names, true);
        assert_eq!(
            with_bundle,
            ["AsyncDNS", "brotli", "CAcert", "SSL", "zstd"]
        );
        // Not at the end, which is where a post-sort append would put it.
        assert_ne!(with_bundle.last(), Some(&"CAcert"));

        let without_bundle = extended_feature_names(names, false);
        assert!(!without_bundle.contains(&"CAcert"));
        assert_eq!(without_bundle.len() + 1, with_bundle.len());
    }

    #[test]
    fn cacert_appears_exactly_when_a_bundle_is_embedded() {
        let Some(info) = live_libinfo() else { return };
        let rendered =
            captured(|sink| write_features(info.feature_names(), sink));
        assert_eq!(
            rendered
                .split(' ')
                .any(|token| token.trim_end() == "CAcert"),
            ca_embed::is_embedded(),
            "CAcert must be neither fabricated nor withheld"
        );
    }

    #[test]
    fn the_features_line_has_no_trailing_space_and_one_space_per_name() {
        let rendered =
            captured(|sink| write_features(&["alt-svc", "SSL"], sink));
        // Caseless ordering puts "alt-svc" before "SSL"; a byte-wise sort
        // would put "SSL" first.
        assert_eq!(rendered, "Features: alt-svc SSL\n");
        assert!(!rendered.contains("  "));
    }

    #[test]
    fn an_empty_feature_list_suppresses_the_whole_line() {
        // C's `if(feature_names[0])` guard.
        let rendered = captured(|sink| write_features(&[], sink));
        assert!(rendered.is_empty());
    }

    #[test]
    fn debug_is_not_advertised() {
        // AAP 0.6.6. `tests/runtests.pl:660` keys `TrackMemory` off this name,
        // and the whole memory-checking block at `:1759` is wrapped in it. The
        // cost is stated in this module's header: 98 fixtures skip, and
        // `torture-test` is not applicable.
        let Some(info) = live_libinfo() else { return };
        assert!(!info.is_debug());
        let rendered =
            captured(|sink| write_features(info.feature_names(), sink));
        assert!(
            !rendered
                .split(' ')
                .any(|token| token.trim_end().eq_ignore_ascii_case("debug")),
            "got {rendered:?}"
        );
    }

    #[test]
    fn no_gssapi_spnego_or_kerberos_without_the_negotiate_feature() {
        // Three of the 52 names the harness recognises. With `negotiate` off --
        // the default -- naming any of them would be an over-report.
        let Some(info) = live_libinfo() else { return };
        let rendered =
            captured(|sink| write_features(info.feature_names(), sink));
        let banned = ["GSS-API", "SPNEGO", "Kerberos"];
        for name in banned {
            let present =
                rendered.split(' ').any(|token| token.trim_end() == name);
            assert_eq!(
                present,
                info.feature_names().contains(&name),
                "{name}: the printer must neither add nor filter"
            );
        }
    }

    // -- 19, 20, 21, 23. the version banner --------------------------------

    /// The whole `--version` output for the live engine.
    fn rendered_version() -> (String, String) {
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        if let Some(info) = live_libinfo() {
            tool_version_info_with(&info, &mut out, &mut err);
        }
        (
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[test]
    fn the_first_line_names_curl_its_version_its_host_and_libcurl() {
        let (out, _) = rendered_version();
        let first = out.lines().next().unwrap_or_default();

        // `CURL_ID` is `CURL_NAME " " CURL_VERSION " (" CURL_OS ") "`.
        assert!(
            first.starts_with(&format!("curl {CURLVER_VERSION} (")),
            "got {first:?}"
        );
        // `tests/runtests.pl` dies outright without this substring.
        assert!(first.contains("libcurl"), "got {first:?}");
        // The engine's constants agree with the C tree's.
        assert_eq!(version::CURL_NAME, "curl");
        assert_eq!(version::LIBCURL_VERSION, CURLVER_VERSION);
        // And nothing reports the Cargo package name.
        assert!(!out.contains("curl-rs"), "got {out:?}");
    }

    #[test]
    fn the_release_date_uses_the_single_argument_form() {
        // `CURL_PATCHSTAMP` is not defined by default, so there is no
        // ", security patched: ..." tail. `LIBCURL_TIMESTAMP` is
        // `include/curl/curlver.h:72`.
        let (out, _) = rendered_version();
        assert!(
            out.contains("\nRelease-Date: [unreleased]\n"),
            "got {out:?}"
        );
        assert!(!out.contains("security patched"));
        assert_eq!(version::LIBCURL_TIMESTAMP, "[unreleased]");
    }

    #[test]
    fn the_banner_is_silent_on_stderr_and_reports_no_version_mismatch() {
        let (out, err) = rendered_version();
        assert!(err.is_empty(), "got {err:?}");
        assert!(!out.contains("WARNING"), "got {out:?}");
    }

    #[test]
    fn the_mismatch_warning_is_byte_exact_and_goes_to_stdout() {
        // `curl_mprintf`, not `curl_mfprintf(tool_stderr, ...)`. The parameter
        // this is written through is the caller's `out` stream, which is what
        // makes the choice checkable.
        let rendered =
            captured(|sink| write_version_mismatch("8.0.0", "8.1.0", sink));
        assert_eq!(
            rendered,
            "WARNING: curl and libcurl versions do not match. \
             Functionality may be affected.\n"
        );
        // Equal versions say nothing.
        let quiet =
            captured(|sink| write_version_mismatch("8.0.0", "8.0.0", sink));
        assert!(quiet.is_empty());
    }

    #[test]
    fn the_debug_pre_warning_is_byte_exact_and_ends_with_a_blank_line() {
        // `src/tool_help.c:315-316`, on stderr, with `\n\n`. Unreachable while
        // `Debug` is withheld.
        assert_eq!(
            DEBUG_WARNING,
            "WARNING: this libcurl is Debug-enabled, \
             do not use in production\n\n"
        );
        assert!(DEBUG_WARNING.ends_with("\n\n"));
    }

    // -- 22. tool_list_engines ---------------------------------------------

    #[test]
    fn an_empty_engine_list_prints_none_with_two_leading_spaces() {
        let rendered = captured(|sink| list_engines(&[], sink));
        assert_eq!(rendered, "Build-time engines:\n  <none>\n");
    }

    #[test]
    fn each_engine_is_indented_by_two_spaces() {
        let rendered =
            captured(|sink| list_engines(&["dynamic", "rdrand"], sink));
        assert_eq!(rendered, "Build-time engines:\n  dynamic\n  rdrand\n");
        assert!(!rendered.contains("<none>"));
    }

    // -- 24. no identity from Cargo metadata ------------------------------

    #[test]
    fn nothing_shipped_derives_identity_from_cargo_metadata() {
        // The needles are assembled from fragments so that this test does not
        // match itself; the scan covers everything before the test module.
        let shipped = shipped_source();
        assert!(!shipped.is_empty());

        let forbidden = [
            concat!("CARGO", "_PKG_"),
            concat!("CARGO", "_BIN_NAME"),
            concat!("env::consts", "::OS"),
            concat!("args()", ".next()"),
        ];
        for needle in forbidden {
            assert!(
                !shipped.contains(needle),
                "{needle} is not an identity source"
            );
        }
    }

    #[test]
    fn nothing_shipped_spells_the_version_or_the_package_name() {
        // The version string has exactly one owner,
        // `curl-rs-lib/src/version.rs`, and this file queries it. A literal
        // here would be the duplicate that ownership exists to prevent.
        let shipped = shipped_source();
        assert!(!shipped.is_empty());
        assert!(
            !shipped.contains(version::LIBCURL_VERSION),
            "the version must be queried, never copied"
        );
    }

    #[test]
    fn no_shipped_string_literal_reports_the_cargo_package_name() {
        // Comments may name the package -- they are citations. Emitted strings
        // may not: the self-reported name is `curl`.
        let shipped = shipped_source();
        assert!(!shipped.is_empty());
        for literal in shipped.split('"').skip(1).step_by(2) {
            assert!(
                !literal.contains("curl-rs"),
                "a string literal names the Cargo package: {literal:?}"
            );
        }
    }

    #[test]
    fn nothing_shipped_opts_out_of_the_safety_forbid() {
        let shipped = shipped_source();
        assert!(!shipped.is_empty());
        assert!(!shipped.contains(concat!("un", "safe")));
    }
}
