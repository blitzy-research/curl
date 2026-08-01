// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Extended attributes recorded alongside a saved download.
//!
//! This module supersedes one C translation unit and its header:
//! `src/tool_xattr.c` (130 lines), which writes extended attributes on saved
//! files, while `src/tool_xattr.h` (49 lines) supplies the
//! build gate and the no-support fallback that this module reproduces.
//!
//! It owns exactly four things and nothing else:
//!
//! 1. The metadata-to-attribute mapping table (`src/tool_xattr.c:31-41`).
//! 2. `stripcredentials`, which removes the username and the password from a
//!    URL before that URL is written to disk (`src/tool_xattr.c:45-75`).
//! 3. The single attribute-setting primitive (`src/tool_xattr.c:77-104`).
//! 4. `fwrite_xattr`, which writes four attributes in a fixed order
//!    (`src/tool_xattr.c:108-129`).
//!
//! `--xattr` is opt-in. `src/tool_operate.c:632` reaches this module only when
//! `config->xattr` is set *and* an output file was actually opened
//! (`outs->fopened && outs->stream`), so nothing here runs on the default
//! path.
//!
//! # The four attributes, in order
//!
//! The mapping table has two rows, but `fwrite_xattr` writes **four**
//! attributes. The order is part of the behaviour being preserved and is
//! reproduced exactly:
//!
//! ```text
//! 1. user.creator          = "curl"                    :111
//! 2. user.xdg.referrer.url = CURLINFO_REFERER           :38, :118
//! 3. user.mime_type        = CURLINFO_CONTENT_TYPE      :39, :118
//! 4. user.xdg.origin.url   = stripcredentials(url)      :125
//! ```
//!
//! Three details of that sequence are easy to get wrong, so each is called
//! out where it is implemented:
//!
//! * `user.creator` is written **first and unconditionally**, and its value is
//!   the byte string `curl` -- a literal in the C source at
//!   `src/tool_xattr.c:111`, not a self-reported program name. It is never
//!   derived from Cargo metadata or from the invoked executable's name.
//! * Row two and row three are **skipped** when the metadata is absent; that
//!   is not an error (`src/tool_xattr.c:117`).
//! * The loop **stops at the first set failure** (`src/tool_xattr.c:114`), and
//!   a `stripcredentials` failure returns non-zero **without** writing row
//!   four (`src/tool_xattr.c:123-124`).
//!
//! `user.mime_type` carries the **server's** `Content-Type` response header,
//! by way of `CURLINFO_CONTENT_TYPE`. It is never inferred from the filename
//! or from the file's contents, which is why no content-type-guessing crate
//! is a dependency of this workspace.
//!
//! # Why the engine is reached through injected ports
//!
//! The C original calls two parts of libcurl directly: `curl_easy_getinfo`
//! for the two mapped attributes (`src/tool_xattr.c:116`) and the public URL
//! API for `stripcredentials` (`src/tool_xattr.c:50-64`). In this workspace
//! both live in the engine crate, behind `curl_rs_lib::easy` and
//! `curl_rs_lib::url`.
//!
//! Neither is named directly here. Both are expressed as *ports* -- narrow
//! traits declared in this module and implemented by the caller -- for one
//! measured reason and one design reason.
//!
//! The measured reason: the two engine items this module would need do not
//! exist yet, and the failure is a **name-resolution** failure at compile time,
//! not a manifest one. Both halves of that were measured rather than assumed,
//! because the distinction decides what a reader should go and look at.
//!
//! The manifest and the dependency graph are sound.
//! `cargo metadata --locked --offline --format-version 1` exits 0 and prints
//! nothing on standard error, and the graph it returns lists a `lib` target
//! named `curl_rs_lib` for the engine crate. `curl-rs-lib` is a declared
//! dependency of this crate and resolves normally.
//!
//! What fails is naming the items. Compiling a probe that mentions both yields
//! two *different* errors, and the difference is the useful part:
//!
//! ```text
//! error[E0433]: cannot find `Url` in `url`
//! error[E0433]: cannot find `easy` in `curl_rs_lib`
//! ```
//!
//! `curl_rs_lib::url` is a real module -- the engine declares it to host
//! `url::idn` -- but the URL type the C original uses is not in it yet.
//! `curl_rs_lib::easy` does not exist at all: the engine's crate root records
//! it among the subsystems that are specified target design and not yet
//! declared, because a `mod` line without its file is `E0583`, a hard error no
//! `#[allow]` can reach.
//!
//! Writing `use curl_rs_lib::url::...` or `use curl_rs_lib::easy::...` would
//! therefore mean guessing a type name and a method signature that nothing can
//! check, and a wrong guess breaks the workspace build rather than just this
//! file.
//!
//! The design reason: dependency injection is the sanctioned mechanism
//! precisely so that a module stays testable without live network access. The
//! ports below are what let the four-attribute sequence be asserted against a
//! recording fake instead of against a real file system.
//!
//! What matters is that no URL parsing and no content-type inference happens
//! in this module. `stripcredentials` performs the *sequence of URL API
//! operations* that the C original performs, with the same flags, and
//! delegates every parsing decision to the injected implementation. Wiring it
//! up needs one adapter over `curl_rs_lib::url` and one over
//! `curl_rs_lib::easy`, both belonging to the call site in
//! `curl-rs/src/operate/`.
//!
//! # `fsetxattr` is reached through the engine's audited island
//!
//! `xattr()` at `src/tool_xattr.c:77-104` is the only place the C original
//! touches the operating system, and it does so in two platform forms:
//!
//! ```text
//! HAVE_FSETXATTR_6  fsetxattr(fd, attr, value, strlen(value), 0, 0)  :89-90
//! HAVE_FSETXATTR_5  fsetxattr(fd, attr, value, strlen(value), 0)     :91-92
//! ```
//!
//! The six-argument form is macOS, the five-argument form is Linux, and
//! between them they cover all four targets in the mandated matrix. A third
//! arm at `:93-100` uses FreeBSD's and MidnightBSD's `extattr_set_fd`; those
//! platforms are out of scope and it is not reproduced.
//!
//! Three independent measurements close off every route to that syscall from
//! *this* crate, and they were taken rather than assumed:
//!
//! 1. `std` has no extended-attribute API at all.
//! 2. No extended-attribute crate is among the workspace pins, and
//!    `curl-rs/Cargo.toml` declares four runtime dependencies -- the engine,
//!    `clap`, `clap_complete` and `tokio` -- none of which offers one. Its two
//!    dev-dependencies, `tempfile` and `tokio`, reach `#[cfg(test)]` code only
//!    and so could not serve a shipped path even if one of them did. Adding a
//!    dependency to reach a syscall is not this file's call.
//! 3. `#![forbid(unsafe_code)]` on `curl-rs/src/main.rs` covers this module,
//!    and this crate has no `mod ffi`, so there is no `#[allow(unsafe_code)]`
//!    anywhere in it to place the call behind.
//!    That literal `forbid` is available here precisely because there is
//!    nothing to exempt: in `curl-rs-lib`, `forbid` plus the inner `allow`
//!    its FFI island needs is `error[E0453]`, so that root carries
//!    `#![deny(unsafe_code)]` with exactly one exemption instead.
//!    `curl-rs/src/main.rs`, `curl-rs/src/bin/curlinfo.rs` and
//!    `curl-rs/build.rs` all carry the literal `forbid` with zero exemptions.
//!
//! None of that means the attribute goes unwritten. AAP section 0.8.5 conflict
//! C3 designates `curl-rs-lib/src/ffi/sys.rs` as the single audited island for
//! exactly this kind of residue, and it publishes
//! `curl_rs_lib::set_file_xattr`: one safe signature over both platform forms,
//! with the `unsafe` block and its `// SAFETY:` justification confined there and
//! the wrapper exercised through the injected `SysCalls` seam. `set_file_xattr`
//! in this module is the adapter onto C's error convention and nothing more.
//!
//! That division is the point of goal G6 rather than a concession to it: the
//! requirement is not that the platform call be skipped, but that it live in one
//! place that can be audited. Everything else in this module -- the attribute
//! names, their order, the skip and abort rules, and `stripcredentials` -- is
//! implemented and tested here, in safe code.
//!
//! # The `errno` travels, because C's warning is built from it
//!
//! The call site is `src/tool_operate.c:632-640`:
//!
//! ```text
//! rc = fwrite_xattr(curl, per->url, fileno(outs->stream));
//! if(rc) {
//!   char errbuf[STRERROR_LEN];
//!   warnf("Error setting extended attributes on '%s': %s", outs->filename,
//!         curlx_strerror(errno, errbuf, sizeof(errbuf)));
//! }
//! ```
//!
//! The `%s` is filled from **`errno`**, not from `rc`. So a failure has to
//! carry the number the syscall set, or the warning cannot be reproduced --
//! which is why [`XattrFailure`] holds an `Option<i32>` rather than being the
//! unit struct a `Result<(), ()>`-shaped reading would suggest. Its two
//! constructors are the two routes C has: [`XattrFailure::from_errno`] for a
//! failed `fsetxattr`, and [`XattrFailure::without_errno`] for the bare
//! `return 1` at `src/tool_xattr.c:124`, which sets no `errno` at all.
//!
//! The system text itself is rendered by
//! [`curl_rs_lib::os_error_message`] -- the one shared helper every
//! diagnostic in the workspace derives its `strerror` text from -- so
//! `curlx_strerror` has exactly one counterpart rather than one per call
//! site.
//!
//! One knock-on effect is recorded so it is not rediscovered by accident.
//! `src/curlinfo.c:176-181` prints `xattr: ` followed by `ON` or `OFF` from
//! `#ifndef USE_XATTR`. Attributes are now written, so the diagnostic binary
//! must report `xattr: ON`; `curl-rs/src/bin/curlinfo.rs` owns that line and
//! `the_diagnostic_binary_agrees_that_xattr_is_on` below is the assertion that
//! keeps the two artifacts from drifting apart.
//!
//! # The `CURL_FAKE_XATTR` hook is documented, not implemented
//!
//! `src/tool_xattr.c:83-88` wraps a test seam in `#ifdef DEBUGBUILD`: when
//! the `CURL_FAKE_XATTR` environment variable is set, the primitive prints
//! `"%s => %s\n"` through `curl_mprintf` -- to standard output, not standard
//! error -- and returns success without calling the syscall.
//!
//! It is not reproduced. The `Debug` feature is deliberately never
//! advertised, and that is what `DEBUGBUILD` backs, so
//! reproducing a `DEBUGBUILD`-only branch would add a code path that no
//! configuration can reach. It is noted because it shows the shape upstream
//! chose for a testable seam, and this module reaches the same end by
//! injecting the writer instead of by reading an environment variable, which
//! keeps the seam out of the shipped binary entirely.
//!
//! # The upstream unit-test corpus
//!
//! `src/tool_xattr.c:44` marks `stripcredentials` with `/* @unittest: 1621 */`.
//! That test is `tests/tunit/tool1621.c`, driven by the fixture
//! `tests/data/test1621`, and it checks eighteen inputs. Such coverage moves
//! into the crate, so the corpus is preserved here
//! verbatim and its assertions are split according to who owns them:
//!
//! ```text
//! ninja://foo@example.com          => (null)      unsupported scheme
//! pop3s://foo@example.com          => pop3s://example.com/
//! ldap://foo@example.com           => ldap://example.com/
//! https://foo@example.com          => https://example.com/
//! https://localhost:45             => https://localhost:45/
//! https://foo@localhost:45         => https://localhost:45/
//! https://user:pass@localhost:45   => https://localhost:45/
//! http://daniel:password@localhost => http://localhost/
//! http://daniel@localhost          => http://localhost/
//! http://localhost/                => http://localhost/
//! http://odd%40host/               => (null)      bad host
//! http://user@odd%40host/          => (null)      bad host
//! http://host/@path/               => http://host/@path/
//! http://emptypw:@host/            => http://host/
//! http://:emptyuser@host/          => http://host/
//! http://odd%40user@host/          => http://host/
//! http://only%40one%40host/        => (null)      bad host
//! http://odder%3auser@host/        => http://host/
//! ```
//!
//! Every row's *outcome* is decided by URL parsing, which belongs to
//! `curl-rs-lib/src/url/`, which deliberately preserves curl's own parsing
//! quirks rather than delegating to a general-purpose URL crate, and fixture
//! `tests/data/test1621` exercises it end to end. What *this* module decides,
//! and what the tests below pin, is the operation sequence, the exact flag
//! sets, and how failure propagates.
//!
//! One row is worth singling out because it is the observable signature of
//! the flag set: `https://foo@example.com` yields `https://example.com/` with
//! **no `:443`**, while the explicit port in `https://localhost:45` survives.
//! A default port would appear only if `CURLU_DEFAULT_PORT` were passed on
//! the get, which is what `curl-rs/src/output/writeout.rs` does for a
//! different purpose and what must not leak in here. `UrlFlags` is shaped so
//! that it cannot.

use std::fmt;
use std::io;
use std::os::fd::BorrowedFd;

/// The attribute naming the program that saved the file
/// (`src/tool_xattr.c:111`).
#[allow(dead_code)]
const ATTR_CREATOR: &str = "user.creator";

/// The value written to [`ATTR_CREATOR`], byte for byte as
/// `src/tool_xattr.c:111` spells it.
///
/// This is the tool's published name, not this crate's package name, and the
/// distinction matters because the value lands in an on-disk artifact that a
/// real curl may later read back. The same literal recurs throughout the C
/// tool: `src/tool_version.h:28` defines `CURL_NAME "curl"`,
/// `src/tool_msgs.c:32` defines `ERROR_PREFIX "curl: "`, and
/// `src/tool_help.c:240` prints `Usage: curl [options...] <url>`. Deriving it
/// from Cargo metadata or from the invoked executable's name would write the
/// wrong bytes, so the literal is spelled out here.
#[allow(dead_code)]
const CREATOR: &str = "curl";

/// The attribute recording where the file came from, credentials removed
/// (`src/tool_xattr.c:125`).
#[allow(dead_code)]
const ATTR_ORIGIN_URL: &str = "user.xdg.origin.url";

/// Which piece of transfer metadata a mapping row asks for.
///
/// A symbolic stand-in for C's `CURLINFO` values that deliberately carries
/// **no integer**. Every public enumerator's numeric value is pinned, and
/// those integers are owned by `curl-rs-ffi/src/ffi/opts.rs` and
/// mirrored in the engine, and a second definition here could only drift from
/// them. The two selectors stand for `CURLINFO_CONTENT_TYPE`
/// (`include/curl/curl.h:2939`, declared as `CURLINFO_STRING + 18`) and
/// `CURLINFO_REFERER` (`include/curl/curl.h:2984`, `CURLINFO_STRING + 60`).
/// Resolving a selector to its integer belongs to the adapter over
/// `curl_rs_lib::easy`, not here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum InfoSelector {
    /// `CURLINFO_REFERER`: the `Referer` header curl sent.
    Referer,
    /// `CURLINFO_CONTENT_TYPE`: the `Content-Type` the **server** returned.
    ///
    /// Server-chosen, therefore never inferred from the filename and never
    /// assumed to be well-formed text.
    ContentType,
}

/// One row of C's `mappings[]` table (`src/tool_xattr.c:31-34`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
struct XattrMapping {
    /// C's `const char *attr`, commented "name of the xattr" at
    /// `src/tool_xattr.c:32`.
    attr: &'static str,
    /// C's `CURLINFO info` at `src/tool_xattr.c:33`.
    info: InfoSelector,
}

/// The mapping table, in C's order (`src/tool_xattr.c:34-41`).
///
/// The names are not curl's invention. C's comment at
/// `src/tool_xattr.c:35-37` records them as "mappings proposed by"
/// <https://freedesktop.org/wiki/CommonExtendedAttributes/>, and that
/// citation is carried here because it is the only justification for these
/// exact spellings.
///
/// C terminates the array with `{ NULL, CURLINFO_NONE }` at
/// `src/tool_xattr.c:40`, commented "last element, abort here", which the
/// `while(!err && mappings[i].attr)` loop at `:114` tests against;
/// `CURLINFO_NONE` is `include/curl/curl.h:2901`, "first, never use this". A
/// Rust slice carries its own length, so that sentinel has nothing left to
/// do and is not reproduced: iterating this slice visits the same two rows in
/// the same order and stops in the same place.
#[allow(dead_code)]
const MAPPINGS: &[XattrMapping] = &[
    XattrMapping {
        attr: "user.xdg.referrer.url",
        info: InfoSelector::Referer,
    },
    XattrMapping {
        attr: "user.mime_type",
        info: InfoSelector::ContentType,
    },
];

/// The URL parts `stripcredentials` addresses.
///
/// Mirrors the three `CURLUPart` enumerators the C original uses:
/// `CURLUPART_URL` (`include/curl/urlapi.h:71`), `CURLUPART_USER` (`:73`) and
/// `CURLUPART_PASSWORD` (`:74`). Carries no integer, for the same reason as
/// [`InfoSelector`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum UrlPart {
    /// `CURLUPART_URL`.
    Url,
    /// `CURLUPART_USER`.
    User,
    /// `CURLUPART_PASSWORD`.
    Password,
}

/// The flag sets `stripcredentials` passes to the URL API, and only those.
///
/// C passes a bit mask. This is an enumeration of the two masks that
/// `src/tool_xattr.c:45-75` actually uses, which turns an easy mistake from
/// discouraged into unrepresentable.
///
/// `curl-rs/src/output/writeout.rs` calls the same URL API for a different
/// purpose and needs a different mask: `CURLU_GUESS_SCHEME` together with
/// `CURLU_NON_SUPPORT_SCHEME` (`include/curl/urlapi.h:90`, `1 << 3`) on the
/// set, and `CURLU_DEFAULT_PORT` (`include/curl/urlapi.h:84`, `1 << 0`) on the
/// get. Unifying the two would change what this module writes to disk:
/// `CURLU_DEFAULT_PORT` turns `https://example.com/` into
/// `https://example.com:443/`, and the corpus in the module documentation
/// shows the former is correct. Since neither of those bits has a variant
/// here, the mistake cannot be made even by copying the wrong line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum UrlFlags {
    /// C's literal `0`, passed at `src/tool_xattr.c:56`, `:60` and `:64`.
    NoFlags,
    /// `CURLU_GUESS_SCHEME` (`include/curl/urlapi.h:96`, `1 << 9`, "legacy
    /// curl-style guessing"), passed only on the URL set at
    /// `src/tool_xattr.c:52`.
    GuessScheme,
}

/// A URL API operation reported failure.
///
/// C compares a `CURLUcode` against zero and branches without ever inspecting
/// which code came back -- `if(uc) goto error` at `src/tool_xattr.c:53`,
/// `:57`, `:61` and `:65`. This type carries no code both for that reason and
/// because those integers are pinned elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct UrlApiFailure;

impl fmt::Display for UrlApiFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("URL API operation failed")
    }
}

impl std::error::Error for UrlApiFailure {}

/// The attribute metadata could not be recorded.
///
/// C returns `int`: zero for success, non-zero for failure
/// (`src/tool_xattr.c:128`). It reaches non-zero by two routes -- `xattr()`'s
/// own return value (`:103`) and the bare `return 1` taken when
/// `stripcredentials` fails (`:124`) -- and neither it nor its caller ever
/// tells them apart by the returned value. `Err` means exactly what C's
/// non-zero means, and the caller's only correct response is the one C takes:
/// warn.
///
/// # Why it carries an `errno`
///
/// The warning is **not** built from the returned value:
///
/// ```text
/// warnf("Error setting extended attributes on '%s': %s", outs->filename,
///       curlx_strerror(errno, errbuf, sizeof(errbuf)));   /* :637-638 */
/// ```
///
/// It reads `errno`, which the failing `fsetxattr` set. Reproducing that
/// diagnostic byte-for-byte therefore requires the number to travel from the
/// syscall to the warning, so it travels in this value rather than in a
/// thread-global that Rust does not expose.
///
/// The two routes differ in exactly one respect, and the difference is C's:
///
/// * A failed `fsetxattr` sets `errno`, so [`Self::errno`] is `Some`.
/// * The `return 1` at `:124` sets no `errno` at all, so [`Self::errno`] is
///   `None`. C's warning still prints one there -- whatever value happened to
///   be left in `errno` by some earlier call -- which is a stale read rather
///   than a described behaviour. `None` records that no number was produced
///   and leaves the caller to decide, instead of inventing one here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct XattrFailure {
    errno: Option<i32>,
}

impl XattrFailure {
    /// The failure a syscall reported, carrying the `errno` it set.
    #[allow(dead_code)]
    pub(crate) const fn from_errno(errno: i32) -> Self {
        Self { errno: Some(errno) }
    }

    /// The `return 1` route at `src/tool_xattr.c:124`, which sets no `errno`.
    #[allow(dead_code)]
    pub(crate) const fn without_errno() -> Self {
        Self { errno: None }
    }

    /// The `errno` for the `%s` of `src/tool_operate.c:637-638`, if there is
    /// one.
    #[allow(dead_code)]
    pub(crate) const fn errno(self) -> Option<i32> {
        self.errno
    }

    /// The operating-system text the warning's `%s` interpolates, if there is
    /// an `errno` to render.
    ///
    /// `curlx_strerror(errno, errbuf, sizeof(errbuf))`, rendered through
    /// [`curl_rs_lib::os_error_message`] so that every diagnostic in the
    /// workspace derives its system text from one helper. Composing the
    /// surrounding warning is the caller's business: that format string is
    /// frozen CLI output owned by the call site, exactly as it is in C.
    #[allow(dead_code)]
    pub(crate) fn os_error_text(self) -> Option<String> {
        self.errno.map(|errno| {
            curl_rs_lib::os_error_message(&io::Error::from_raw_os_error(errno))
        })
    }
}

impl fmt::Display for XattrFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("extended attribute metadata could not be recorded")
    }
}

impl std::error::Error for XattrFailure {}

/// Read access to a transfer's metadata: the port for `curl_easy_getinfo`.
///
/// Implemented by the call site over `curl_rs_lib::easy`, for the reasons in
/// the module documentation.
#[allow(dead_code)]
pub(crate) trait TransferInfo {
    /// The string metadata for `info`, or `None` when there is none.
    ///
    /// Mirrors `curl_easy_getinfo(curl, mappings[i].info, &value)` at
    /// `src/tool_xattr.c:116`, whose outcome the next line tests as
    /// `if(!result && value)`. Those are two distinct C conditions -- the call
    /// failed, or it succeeded and handed back `NULL` -- and `:117` treats
    /// them identically, skipping the row either way, so they collapse into a
    /// single `None` here.
    ///
    /// Bytes rather than a `String`: C takes a `char *` and measures it with
    /// `strlen` (`src/tool_xattr.c:90`), and `CURLINFO_CONTENT_TYPE` carries a
    /// value the remote server chose, which must not be assumed to be valid
    /// UTF-8.
    fn info_string(&self, info: InfoSelector) -> Option<Vec<u8>>;
}

/// One URL handle: the port for `curl_url_set` and `curl_url_get`.
///
/// Implemented by the call site over `curl_rs_lib::url`, whose parsing
/// deliberately preserves curl's own quirks. Every parsing decision belongs to
/// that implementation; this module only chooses the operations and their
/// flags.
#[allow(dead_code)]
pub(crate) trait CurlUrlApi {
    /// Sets `part`, or removes it when `value` is `None`.
    ///
    /// Mirrors `curl_url_set` at `src/tool_xattr.c:52`, `:56` and `:60`. C
    /// passes a null pointer to remove a part -- which is the entire mechanism
    /// by which the credentials are dropped -- and `None` expresses that.
    fn set(
        &mut self,
        part: UrlPart,
        value: Option<&str>,
        flags: UrlFlags,
    ) -> Result<(), UrlApiFailure>;

    /// Reads `part` back out.
    ///
    /// Mirrors `curl_url_get(u, CURLUPART_URL, &nurl, 0)` at
    /// `src/tool_xattr.c:64`. C hands back a heap pointer that the caller must
    /// release with `curl_free` (`:126`); an owned `String` carries that
    /// obligation in the type instead.
    fn get(
        &self,
        part: UrlPart,
        flags: UrlFlags,
    ) -> Result<String, UrlApiFailure>;
}

/// Creation of URL handles: the port for `curl_url`.
#[allow(dead_code)]
pub(crate) trait UrlApiFactory {
    /// A fresh, empty URL handle, or `None` if one cannot be created.
    ///
    /// Mirrors `u = curl_url();` and the `if(u)` that guards everything after
    /// it (`src/tool_xattr.c:50-51`): a null handle makes the whole function
    /// give up and return `NULL` (`:74`).
    ///
    /// The handle is boxed so this trait stays object-safe. Dropping the box
    /// replaces C's explicit `curl_url_cleanup(u)`, which C must call on both
    /// the success path (`:68`) and the error path (`:73`) -- an RAII
    /// boundary that cannot be forgotten on either path.
    fn new_url(&self) -> Option<Box<dyn CurlUrlApi>>;
}

/// Where an attribute is actually recorded: the seam that isolates the
/// syscall, and the seam the tests substitute at.
///
/// Private deliberately. The only production implementation is
/// [`FileXattrWriter`]; the only other is the recording fake in this module's
/// tests, which is what allows the attribute sequence to be asserted without
/// touching a file system and without an environment variable
/// (contrast C's `CURL_FAKE_XATTR` hook, discussed in the module
/// documentation).
#[allow(dead_code)]
trait XattrWriter {
    /// Records one attribute under `attr` with the exact bytes `value`.
    fn write_xattr(
        &mut self,
        attr: &str,
        value: &[u8],
    ) -> Result<(), XattrFailure>;
}

/// The production writer: attributes destined for an open file descriptor.
#[allow(dead_code)]
struct FileXattrWriter<'fd> {
    /// The descriptor C receives as `int fd` (`src/tool_xattr.c:77`).
    ///
    /// Borrowed rather than owned. The C caller passes
    /// `fileno(outs->stream)` (`src/tool_operate.c:634`), so the descriptor
    /// belongs to the output stream: this writer must neither close it nor
    /// outlive it, and `BorrowedFd` states both.
    fd: BorrowedFd<'fd>,
}

impl XattrWriter for FileXattrWriter<'_> {
    fn write_xattr(
        &mut self,
        attr: &str,
        value: &[u8],
    ) -> Result<(), XattrFailure> {
        set_file_xattr(self.fd, attr, value)
    }
}

/// Sets one extended attribute on an open file, through the engine.
///
/// # What C does here
///
/// `xattr()` at `src/tool_xattr.c:77-104` issues the syscall in one of two
/// platform forms, both of which are needed by the mandated four-target
/// matrix:
///
/// ```text
/// HAVE_FSETXATTR_6  fsetxattr(fd, attr, value, strlen(value), 0, 0)  :89-90
/// HAVE_FSETXATTR_5  fsetxattr(fd, attr, value, strlen(value), 0)     :91-92
/// ```
///
/// The six-argument form is macOS, so it covers `x86_64-apple-darwin` and
/// `aarch64-apple-darwin`; the five-argument form is Linux, covering
/// `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`. C's third arm
/// at `:93-100` uses FreeBSD's and MidnightBSD's `extattr_set_fd` and returns
/// `rc < 0 ? -1 : 0` because that call returns a length rather than a status;
/// those platforms are out of scope and it is not reproduced.
///
/// # Why the call is made in the engine rather than here
///
/// Three of the ordinary local routes to the syscall are closed, and each was
/// measured rather than assumed: `std` exposes no extended-attribute API, no
/// extended-attribute crate is among the workspace pins -- `curl-rs/Cargo.toml`
/// declares four runtime dependencies, the engine, `clap`, `clap_complete` and
/// `tokio`, and adding a fifth to reach a syscall is not this file's decision
/// -- and `unsafe` is unavailable, because `#![forbid(unsafe_code)]` on
/// `curl-rs/src/main.rs` covers this module and this crate has no `mod ffi` to
/// place a raw call behind. The module documentation records each with its
/// measurement, and why `curl-rs-lib` carries `#![deny(unsafe_code)]` with one
/// exemption instead. What is left is not a gap: the fourth route is open, and
/// it is the sanctioned one -- the engine's audited island makes the call.
///
/// AAP section 0.8.5 conflict C3 answers that by designating
/// `curl-rs-lib/src/ffi/sys.rs` as the single audited island for operating-system
/// residue, and `curl_rs_lib::set_file_xattr` is the wrapper it publishes: one
/// signature over both the five-argument Linux form and the six-argument macOS
/// form, with the `unsafe` block and its `// SAFETY:` justification confined
/// there. This function is the adapter between that and C's error convention,
/// and nothing more.
///
/// [`curl_rs_lib::set_file_xattr`] selects between the five-argument and
/// six-argument forms behind that one signature, so no platform conditional
/// appears in this crate, and it reports failure as an [`io::Error`] carrying
/// the `errno` the syscall set. That number is what
/// `src/tool_operate.c:637-638` interpolates, so it is preserved here in
/// [`XattrFailure`] rather than discarded.
///
/// # What the engine reports, and how it maps
///
/// The engine distinguishes an impossible attribute name from a platform
/// refusal. C does not: `xattr()` collapses every failure into `-1` and
/// `src/tool_operate.c:635` inspects only whether one occurred. Both
/// therefore become one [`XattrFailure`] here -- carrying the `errno` when
/// there is one -- which is what keeps the first-error-wins accounting in
/// [`fwrite_xattr_with`] identical to C's. A refusal is routine rather than
/// exceptional, since a filesystem need not support extended attributes at
/// all, and C treats it that way: it warns once and completes the transfer.
/// `--xattr` is opt-in, so no default path is affected either.
///
/// # Errors
///
/// Returns [`XattrFailure::from_errno`] with the syscall's `errno` whenever
/// `fsetxattr` fails -- most commonly `ENOTSUP` on a file system mounted
/// without extended-attribute support, or `EPERM` on one that forbids the
/// `user.` namespace. C's caller warns and carries on, and nothing here
/// escalates that.
///
/// An [`io::Error`] with no raw `errno` cannot arise from this call, since the
/// engine builds it with `io::Error::last_os_error`. Should the standard
/// library ever produce one anyway, it is reported as a failure without a
/// number rather than being silently mapped onto a plausible-looking one.
#[allow(dead_code)]
fn set_file_xattr(
    fd: BorrowedFd<'_>,
    attr: &str,
    value: &[u8],
) -> Result<(), XattrFailure> {
    // `attr` crosses as bytes: the engine wrapper builds the `CString` the
    // syscall needs, because appending the NUL is its side of the boundary.
    // `value` is passed with its own length rather than NUL-terminated, which
    // is C's `strlen(value)` at `:89`/`:91` computed on the Rust side.
    curl_rs_lib::set_file_xattr(fd, attr.as_bytes(), value).map_err(|error| {
        match error.raw_os_error() {
            Some(errno) => XattrFailure::from_errno(errno),
            None => XattrFailure::without_errno(),
        }
    })
}

/// The counterpart of C's `xattr()` (`src/tool_xattr.c:77-104`): the
/// absent-value guard, and then the write.
///
/// Split from [`set_file_xattr`] so that the guard applies to every writer,
/// the production one and the test fake alike, exactly as C's guard applies
/// ahead of every platform arm.
#[allow(dead_code)]
fn set_xattr(
    sink: &mut dyn XattrWriter,
    attr: &str,
    value: Option<&[u8]>,
) -> Result<(), XattrFailure> {
    match value {
        // `if(value)` at src/tool_xattr.c:82. C initialises `err = 0` at :81
        // and skips the entire body when the pointer is null, so an absent
        // value is a no-op that reports success: no attribute is written and
        // no error is raised.
        None => Ok(()),
        Some(value) => sink.write_xattr(attr, value),
    }
}

/// Returns `url` with its user name and password removed, or `None` if the URL
/// API refuses any step.
///
/// The counterpart of `stripcredentials()` at `src/tool_xattr.c:45-75`, marked
/// there `/* @unittest: 1621 */` (`:44`) and commented "returns a new URL that
/// needs to be freed" (`:43`) -- an obligation the returned `String` discharges
/// by itself.
///
/// The credentials are not edited out textually. They are removed by setting
/// the two parts to nothing and asking the URL API to reassemble what is left,
/// which is why the output can differ from the input in other ways too: the
/// corpus in the module documentation shows `http://daniel@localhost` becoming
/// `http://localhost/`, with a path appearing that the input did not have.
///
/// # The five operations, and their flags
///
/// The sequence and the flags are the whole of this function's contract:
///
/// 1. `curl_url()` -- a null handle ends it (`:50-51`, `:74`).
/// 2. Set the URL with `CURLU_GUESS_SCHEME`, **and no other flag** (`:52`).
/// 3. Remove the username: set it to nothing, no flags (`:56`).
/// 4. Remove the password: set it to nothing, no flags (`:60`).
/// 5. Read the URL back with **no flags at all** (`:64`).
///
/// Any failure gives `None`; C reaches its `error:` label from each of the four
/// checks at `:53`, `:57`, `:61` and `:65` and returns `NULL` (`:74`). C's
/// `curl_url_cleanup(u)` on both paths (`:68`, `:73`) is the drop of `handle`.
///
/// Step 5 taking no flags is the detail most easily lost. Passing
/// `CURLU_DEFAULT_PORT` there -- as `curl-rs/src/output/writeout.rs` correctly
/// does for its own purpose -- would append `:443` to every HTTPS origin
/// recorded on disk. [`UrlFlags`] cannot express that flag, so the sequence
/// below is the only one this module can perform.
#[allow(dead_code)]
pub(crate) fn stripcredentials(
    urls: &dyn UrlApiFactory,
    url: &str,
) -> Option<String> {
    // src/tool_xattr.c:50-51 -- `u = curl_url(); if(u) {`. Everything after
    // this point is inside C's `if`, and a null handle falls straight through
    // to the `error:` label's `return NULL` at :74.
    let mut handle = urls.new_url()?;

    // src/tool_xattr.c:52 -- CURLU_GUESS_SCHEME, deliberately alone.
    handle
        .set(UrlPart::Url, Some(url), UrlFlags::GuessScheme)
        .ok()?;

    // src/tool_xattr.c:56 -- a null value removes the part. This is the step
    // that drops the username.
    handle.set(UrlPart::User, None, UrlFlags::NoFlags).ok()?;

    // src/tool_xattr.c:60 -- likewise for the password.
    handle
        .set(UrlPart::Password, None, UrlFlags::NoFlags)
        .ok()?;

    // src/tool_xattr.c:64 -- flags 0. See the note above on why.
    let stripped = handle.get(UrlPart::Url, UrlFlags::NoFlags).ok()?;

    // src/tool_xattr.c:68 -- `curl_url_cleanup(u)` happens as `handle` drops.
    Some(stripped)
}

/// Writes the four attributes through `sink`, in C's order.
///
/// The whole of `fwrite_xattr`'s logic (`src/tool_xattr.c:108-129`) lives here,
/// parameterised by the writer so that the sequence can be observed. The
/// public entry point [`fwrite_xattr`] supplies the production writer.
#[allow(dead_code)]
fn fwrite_xattr_with(
    info: &dyn TransferInfo,
    urls: &dyn UrlApiFactory,
    url: &str,
    sink: &mut dyn XattrWriter,
) -> Result<(), XattrFailure> {
    // src/tool_xattr.c:111 -- `int err = xattr(fd, "user.creator", "curl");`
    //
    // First, unconditional, and a literal value. In C this statement
    // initialises `err`, so a failure here also skips the loop below, whose
    // condition is `!err` -- which `?` reproduces by returning at once.
    set_xattr(sink, ATTR_CREATOR, Some(CREATOR.as_bytes()))?;

    // src/tool_xattr.c:113-120 -- "loop through all xattr-curlinfo pairs and
    // abort on a set error".
    for mapping in MAPPINGS {
        // src/tool_xattr.c:116-117 -- `if(!result && value)`. An absent value
        // skips this row and is not an error, so the loop continues to the
        // next one; only a *set* failure stops it.
        let value = info.info_string(mapping.info);

        // src/tool_xattr.c:118. `?` here is C's loop condition `!err` at :114:
        // the first set failure ends the loop, and because C then finds `err`
        // non-zero at :121 it also skips the origin URL and returns `err` at
        // :128 -- which is precisely returning early.
        set_xattr(sink, mapping.attr, value.as_deref())?;
    }

    // src/tool_xattr.c:121-127. Reached only when nothing has failed, matching
    // C's `if(!err)` at :121.
    //
    // src/tool_xattr.c:123-124 -- `if(!nurl) return 1;`. C returns non-zero
    // *without* writing the attribute, and without consulting `err`; the
    // caller's warning follows. `ok_or` reproduces that exactly.
    //
    // This route sets no `errno`, so the failure carries none:
    // `XattrFailure::without_errno` is documented against this exact line.
    let stripped =
        stripcredentials(urls, url).ok_or(XattrFailure::without_errno())?;

    // src/tool_xattr.c:125 -- the fourth and last attribute. C frees `nurl` at
    // :126; `stripped` drops at the end of this function.
    set_xattr(sink, ATTR_ORIGIN_URL, Some(stripped.as_bytes()))
}

/// Stores the transfer's metadata alongside the downloaded file, using
/// extended attributes.
///
/// The counterpart of `fwrite_xattr(CURL *curl, const char *url, int fd)` at
/// `src/tool_xattr.c:108`, declared at `src/tool_xattr.h:39` and commented at
/// `:105-107` as storing "metadata from the curl request alongside the
/// downloaded file using extended attributes".
///
/// `info` and `urls` are the injected ports described in the module
/// documentation; `url` and `fd` are C's own second and third arguments. The
/// call site is `src/tool_operate.c:632-640`, which reaches this function only
/// when `--xattr` was given and an output file was opened.
///
/// # Errors
///
/// [`XattrFailure`] is C's non-zero return, and the caller's response is fixed
/// by C's: warn once, naming the output file and the `errno` text, and carry on
/// (`src/tool_operate.c:636-638`). `Ok(())` is C's zero, on which the caller
/// emits nothing at all.
///
/// Two routes reach it, and they differ in what the warning can say. A failed
/// `fsetxattr` supplies an `errno`, so [`XattrFailure::os_error_text`] yields
/// the text for the warning's `%s`; a `stripcredentials` failure -- C's
/// `return 1` at `src/tool_xattr.c:124` -- supplies none, and yields `None`.
/// A platform refusal is routine rather than exceptional -- a filesystem need
/// not support extended attributes -- and C collapses it into the same
/// non-zero return, warning once and carrying on.
#[allow(dead_code)]
pub(crate) fn fwrite_xattr(
    info: &dyn TransferInfo,
    urls: &dyn UrlApiFactory,
    url: &str,
    fd: BorrowedFd<'_>,
) -> Result<(), XattrFailure> {
    let mut sink = FileXattrWriter { fd };
    fwrite_xattr_with(info, urls, url, &mut sink)
}

#[cfg(test)]
mod tests {
    use super::{
        fwrite_xattr, fwrite_xattr_with, set_file_xattr, set_xattr,
        stripcredentials, CurlUrlApi, InfoSelector, TransferInfo,
        UrlApiFactory, UrlApiFailure, UrlFlags, UrlPart, XattrFailure,
        XattrWriter, ATTR_CREATOR, ATTR_ORIGIN_URL, CREATOR, MAPPINGS,
    };
    use std::cell::RefCell;
    use std::os::fd::AsFd;
    use std::rc::Rc;

    /// A URL carrying both a username and a password, as `--xattr` would see
    /// it after a transfer authenticated on the command line. The placeholder
    /// credentials copy upstream's own vocabulary at
    /// `tests/tunit/tool1621.c:51`, and `example.com` is reserved by
    /// RFC 2606, so no value here can resemble a real credential.
    const CREDENTIALED: &str = "https://user:pass@example.com/file.bin";

    /// What the URL API returns for [`CREDENTIALED`] once both parts are
    /// removed. Note the absence of `:443`, discussed on `UrlFlags`.
    const STRIPPED: &str = "https://example.com/file.bin";

    /// The `errno` the recording fake reports when it refuses a write.
    ///
    /// `ENOTSUP` is 95 on both Linux targets and 45 on both Apple ones, so it
    /// is taken from the platform rather than written down; a literal would be
    /// wrong on half the mandated matrix. The number itself is incidental --
    /// what the tests assert is that whichever number the syscall produced
    /// reaches the caller unchanged, since `src/tool_operate.c:637-638`
    /// interpolates it.
    #[cfg(target_os = "linux")]
    const REFUSAL_ERRNO: i32 = 95;

    /// `ENOTSUP` on the two Apple targets. See the Linux definition above.
    #[cfg(not(target_os = "linux"))]
    const REFUSAL_ERRNO: i32 = 45;

    /// The upstream `@unittest: 1621` corpus, transcribed from
    /// `tests/tunit/tool1621.c:39-67`. `None` is C's `"(null)"`.
    ///
    /// The rows guarded in C by `USE_SSL`, `CURL_DISABLE_POP3`,
    /// `CURL_DISABLE_LDAP` and `CURL_DISABLE_HTTP` are all present here: those
    /// guards exist so the C test can run against a stripped-down build, and
    /// they do not change what any single row asserts.
    const CORPUS: &[(&str, Option<&str>)] = &[
        // Unsupported scheme.
        ("ninja://foo@example.com", None),
        ("pop3s://foo@example.com", Some("pop3s://example.com/")),
        ("ldap://foo@example.com", Some("ldap://example.com/")),
        ("https://foo@example.com", Some("https://example.com/")),
        ("https://localhost:45", Some("https://localhost:45/")),
        ("https://foo@localhost:45", Some("https://localhost:45/")),
        (
            "https://user:pass@localhost:45",
            Some("https://localhost:45/"),
        ),
        (
            "http://daniel:password@localhost",
            Some("http://localhost/"),
        ),
        ("http://daniel@localhost", Some("http://localhost/")),
        ("http://localhost/", Some("http://localhost/")),
        // Bad host.
        ("http://odd%40host/", None),
        ("http://user@odd%40host/", None),
        ("http://host/@path/", Some("http://host/@path/")),
        ("http://emptypw:@host/", Some("http://host/")),
        ("http://:emptyuser@host/", Some("http://host/")),
        ("http://odd%40user@host/", Some("http://host/")),
        // Bad host.
        ("http://only%40one%40host/", None),
        ("http://odder%3auser@host/", Some("http://host/")),
    ];

    /// One attribute exactly as a writer received it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Written {
        attr: String,
        value: Vec<u8>,
    }

    /// A writer that records instead of writing, and can be told to refuse a
    /// chosen call.
    ///
    /// This is the seam that C reaches with the `CURL_FAKE_XATTR` environment
    /// variable under `DEBUGBUILD` (`src/tool_xattr.c:83-88`). Injecting the
    /// writer keeps the seam out of the shipped binary entirely, which is why
    /// that branch is documented rather than reproduced.
    struct RecordingWriter {
        written: Vec<Written>,
        /// One-based index of the call that fails; `None` never fails.
        refuse_call: Option<usize>,
        calls: usize,
    }

    impl RecordingWriter {
        fn new() -> Self {
            Self {
                written: Vec::new(),
                refuse_call: None,
                calls: 0,
            }
        }

        fn refusing_call(refuse_call: usize) -> Self {
            Self {
                written: Vec::new(),
                refuse_call: Some(refuse_call),
                calls: 0,
            }
        }

        /// The attribute names, in the order they were written.
        fn names(&self) -> Vec<&str> {
            self.written.iter().map(|w| w.attr.as_str()).collect()
        }

        /// The bytes recorded under `attr`, if any.
        fn value_of(&self, attr: &str) -> Option<&[u8]> {
            self.written
                .iter()
                .find(|w| w.attr == attr)
                .map(|w| w.value.as_slice())
        }
    }

    impl XattrWriter for RecordingWriter {
        fn write_xattr(
            &mut self,
            attr: &str,
            value: &[u8],
        ) -> Result<(), XattrFailure> {
            self.calls += 1;
            if self.refuse_call == Some(self.calls) {
                // A refused write records nothing, matching a failed
                // `fsetxattr`: the attribute does not appear on the file.
                //
                // ENOTSUP is the errno a real refusal carries most often --
                // a file system mounted without extended-attribute support --
                // so the fake reports it and the tests can assert that the
                // number reaches the caller rather than being dropped.
                return Err(XattrFailure::from_errno(REFUSAL_ERRNO));
            }
            self.written.push(Written {
                attr: attr.to_owned(),
                value: value.to_vec(),
            });
            Ok(())
        }
    }

    /// Transfer metadata with each of the two mapped values independently
    /// present or absent.
    struct FakeInfo {
        referer: Option<Vec<u8>>,
        content_type: Option<Vec<u8>>,
    }

    impl FakeInfo {
        fn both() -> Self {
            Self {
                referer: Some(b"https://referrer.example/".to_vec()),
                content_type: Some(b"text/html; charset=UTF-8".to_vec()),
            }
        }

        /// Both absent: `curl_easy_getinfo` failed, or handed back `NULL`.
        fn neither() -> Self {
            Self {
                referer: None,
                content_type: None,
            }
        }
    }

    impl TransferInfo for FakeInfo {
        fn info_string(&self, info: InfoSelector) -> Option<Vec<u8>> {
            match info {
                InfoSelector::Referer => self.referer.clone(),
                InfoSelector::ContentType => self.content_type.clone(),
            }
        }
    }

    /// One URL API operation, with the flags it carried.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum UrlOp {
        Set(UrlPart, Option<String>, UrlFlags),
        Get(UrlPart, UrlFlags),
    }

    /// Which step of the URL sequence the fake refuses.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum UrlRefusal {
        Never,
        /// `curl_url()` itself returns nothing (`src/tool_xattr.c:50-51`).
        Creation,
        /// The URL does not parse: C's "unsupported scheme" and "bad host"
        /// corpus rows both land here (`:52-54`).
        SetUrl,
        SetUser,
        SetPassword,
        Get,
    }

    /// The shared operation log, so a handle's record outlives its drop.
    type UrlLog = Rc<RefCell<Vec<UrlOp>>>;

    struct FakeUrl {
        log: UrlLog,
        refusal: UrlRefusal,
        answer: String,
    }

    impl CurlUrlApi for FakeUrl {
        fn set(
            &mut self,
            part: UrlPart,
            value: Option<&str>,
            flags: UrlFlags,
        ) -> Result<(), UrlApiFailure> {
            self.log.borrow_mut().push(UrlOp::Set(
                part,
                value.map(str::to_owned),
                flags,
            ));
            let refused = matches!(
                (self.refusal, part),
                (UrlRefusal::SetUrl, UrlPart::Url)
                    | (UrlRefusal::SetUser, UrlPart::User)
                    | (UrlRefusal::SetPassword, UrlPart::Password)
            );
            if refused {
                Err(UrlApiFailure)
            } else {
                Ok(())
            }
        }

        fn get(
            &self,
            part: UrlPart,
            flags: UrlFlags,
        ) -> Result<String, UrlApiFailure> {
            self.log.borrow_mut().push(UrlOp::Get(part, flags));
            if self.refusal == UrlRefusal::Get {
                Err(UrlApiFailure)
            } else {
                Ok(self.answer.clone())
            }
        }
    }

    struct FakeUrls {
        log: UrlLog,
        refusal: UrlRefusal,
        answer: String,
    }

    impl FakeUrls {
        fn answering(answer: &str) -> Self {
            Self {
                log: Rc::new(RefCell::new(Vec::new())),
                refusal: UrlRefusal::Never,
                answer: answer.to_owned(),
            }
        }

        fn refusing(refusal: UrlRefusal) -> Self {
            Self {
                log: Rc::new(RefCell::new(Vec::new())),
                refusal,
                answer: String::new(),
            }
        }

        fn ops(&self) -> Vec<UrlOp> {
            self.log.borrow().clone()
        }
    }

    impl UrlApiFactory for FakeUrls {
        fn new_url(&self) -> Option<Box<dyn CurlUrlApi>> {
            if self.refusal == UrlRefusal::Creation {
                return None;
            }
            Some(Box::new(FakeUrl {
                log: Rc::clone(&self.log),
                refusal: self.refusal,
                answer: self.answer.clone(),
            }))
        }
    }

    /// The four operations `stripcredentials` must perform on `input`, with
    /// the exact flags C passes.
    fn expected_ops(input: &str) -> Vec<UrlOp> {
        vec![
            UrlOp::Set(
                UrlPart::Url,
                Some(input.to_owned()),
                UrlFlags::GuessScheme,
            ),
            UrlOp::Set(UrlPart::User, None, UrlFlags::NoFlags),
            UrlOp::Set(UrlPart::Password, None, UrlFlags::NoFlags),
            UrlOp::Get(UrlPart::Url, UrlFlags::NoFlags),
        ]
    }

    // stripcredentials -- the relocated `@unittest: 1621` coverage

    #[test]
    fn stripcredentials_removes_the_user_and_the_password() {
        let urls = FakeUrls::answering(STRIPPED);

        let got = stripcredentials(&urls, CREDENTIALED);

        assert_eq!(got.as_deref(), Some(STRIPPED));
        // The credentials are removed by setting both parts to nothing, which
        // is the mechanism at src/tool_xattr.c:56 and :60 -- not by editing
        // the string.
        assert_eq!(urls.ops(), expected_ops(CREDENTIALED));
    }

    #[test]
    fn stripcredentials_leaves_a_credential_free_url_untouched() {
        let plain = "http://localhost/";
        let urls = FakeUrls::answering(plain);

        assert_eq!(stripcredentials(&urls, plain).as_deref(), Some(plain));
    }

    #[test]
    fn stripcredentials_offers_a_scheme_less_input_to_guess_scheme() {
        // CURLU_GUESS_SCHEME is what lets curl accept an input with no scheme
        // at all (include/curl/urlapi.h:96, "legacy curl-style guessing").
        let bare = "example.com/file.bin";
        let urls = FakeUrls::answering("http://example.com/file.bin");

        let got = stripcredentials(&urls, bare);

        assert_eq!(got.as_deref(), Some("http://example.com/file.bin"));
        assert_eq!(
            urls.ops().first(),
            Some(&UrlOp::Set(
                UrlPart::Url,
                Some(bare.to_owned()),
                UrlFlags::GuessScheme
            ))
        );
    }

    #[test]
    fn stripcredentials_fails_when_the_url_will_not_parse() {
        // Both of C's `(null)` causes -- "unsupported scheme" and "bad host" --
        // are a refused CURLUPART_URL set at src/tool_xattr.c:52-54.
        let urls = FakeUrls::refusing(UrlRefusal::SetUrl);

        assert_eq!(stripcredentials(&urls, "ninja://foo@example.com"), None);
        // The refusal is observed on the set, so no later step is attempted.
        assert_eq!(urls.ops().len(), 1);
    }

    #[test]
    fn stripcredentials_gives_up_when_no_handle_can_be_made() {
        // src/tool_xattr.c:51 -- `if(u)`; a null handle falls through to
        // `return NULL` at :74 without touching the URL at all.
        let urls = FakeUrls::refusing(UrlRefusal::Creation);

        assert_eq!(stripcredentials(&urls, CREDENTIALED), None);
        assert_eq!(urls.ops(), Vec::new());
    }

    #[test]
    fn stripcredentials_propagates_a_failure_from_every_later_step() {
        // src/tool_xattr.c:57, :61 and :65 each `goto error`, so each of these
        // must produce None exactly as the URL set does.
        for (refusal, ops) in [
            (UrlRefusal::SetUser, 2),
            (UrlRefusal::SetPassword, 3),
            (UrlRefusal::Get, 4),
        ] {
            let urls = FakeUrls::refusing(refusal);

            assert_eq!(
                stripcredentials(&urls, CREDENTIALED),
                None,
                "refusal {refusal:?}"
            );
            assert_eq!(urls.ops().len(), ops, "refusal {refusal:?}");
        }
    }

    #[test]
    fn stripcredentials_reproduces_the_upstream_corpus() {
        for &(input, expected) in CORPUS {
            match expected {
                None => {
                    let urls = FakeUrls::refusing(UrlRefusal::SetUrl);
                    assert_eq!(
                        stripcredentials(&urls, input),
                        None,
                        "input {input}"
                    );
                }
                Some(want) => {
                    let urls = FakeUrls::answering(want);
                    assert_eq!(
                        stripcredentials(&urls, input).as_deref(),
                        Some(want),
                        "input {input}"
                    );
                    // Every row goes through the same four operations with the
                    // same flags; nothing about the input changes them.
                    assert_eq!(
                        urls.ops(),
                        expected_ops(input),
                        "input {input}"
                    );
                }
            }
        }
    }

    #[test]
    fn stripcredentials_never_asks_for_a_default_port() {
        // The observable signature of the flag set. Passing
        // CURLU_DEFAULT_PORT on the get -- which
        // curl-rs/src/output/writeout.rs correctly does for its own purpose --
        // would turn https://example.com/ into https://example.com:443/. The
        // get must therefore carry no flags at all (src/tool_xattr.c:64), and
        // UrlFlags has no variant that could express otherwise.
        let urls = FakeUrls::answering("https://example.com/");

        let got = stripcredentials(&urls, "https://foo@example.com");

        assert_eq!(got.as_deref(), Some("https://example.com/"));
        assert_eq!(
            urls.ops().last(),
            Some(&UrlOp::Get(UrlPart::Url, UrlFlags::NoFlags))
        );
        // An explicit port survives, so the absence above is the default port
        // being withheld and not ports being dropped.
        let ported = FakeUrls::answering("https://localhost:45/");
        assert_eq!(
            stripcredentials(&ported, "https://localhost:45").as_deref(),
            Some("https://localhost:45/")
        );
    }

    #[test]
    fn stripcredentials_sets_only_guess_scheme_and_only_on_the_url() {
        let urls = FakeUrls::answering(STRIPPED);

        let _ = stripcredentials(&urls, CREDENTIALED);

        for op in urls.ops() {
            let flags = match op {
                UrlOp::Set(part, _, flags) => {
                    if part == UrlPart::Url {
                        assert_eq!(flags, UrlFlags::GuessScheme);
                        continue;
                    }
                    flags
                }
                UrlOp::Get(_, flags) => flags,
            };
            assert_eq!(flags, UrlFlags::NoFlags);
        }
    }

    // The mapping table

    #[test]
    fn the_mapping_table_holds_exactly_the_two_documented_rows() {
        // src/tool_xattr.c:38-40. The two rows, in order; C's third element
        // `{ NULL, CURLINFO_NONE }` is the array terminator and is expressed
        // by this slice's length.
        assert_eq!(MAPPINGS.len(), 2);
        assert_eq!(MAPPINGS[0].attr, "user.xdg.referrer.url");
        assert_eq!(MAPPINGS[0].info, InfoSelector::Referer);
        assert_eq!(MAPPINGS[1].attr, "user.mime_type");
        assert_eq!(MAPPINGS[1].info, InfoSelector::ContentType);
    }

    // fwrite_xattr -- order, values, skipping and aborting

    #[test]
    fn the_four_attributes_are_written_in_c_order() {
        let info = FakeInfo::both();
        let urls = FakeUrls::answering(STRIPPED);
        let mut writer = RecordingWriter::new();

        let got = fwrite_xattr_with(&info, &urls, CREDENTIALED, &mut writer);

        assert_eq!(got, Ok(()));
        assert_eq!(
            writer.names(),
            vec![
                "user.creator",
                "user.xdg.referrer.url",
                "user.mime_type",
                "user.xdg.origin.url",
            ]
        );
    }

    #[test]
    fn the_creator_attribute_is_the_literal_curl() {
        let info = FakeInfo::both();
        let urls = FakeUrls::answering(STRIPPED);
        let mut writer = RecordingWriter::new();

        let _ = fwrite_xattr_with(&info, &urls, CREDENTIALED, &mut writer);

        // src/tool_xattr.c:111. The published tool name, not this crate's
        // package name: the bytes land in an on-disk artifact.
        assert_eq!(writer.value_of(ATTR_CREATOR), Some(&b"curl"[..]));
        assert_eq!(CREATOR, "curl");
        assert_eq!(ATTR_CREATOR, "user.creator");
        // Written first, before any metadata is consulted.
        assert_eq!(writer.names().first(), Some(&"user.creator"));
    }

    #[test]
    fn the_mapped_values_come_from_the_transfer_metadata() {
        let info = FakeInfo::both();
        let urls = FakeUrls::answering(STRIPPED);
        let mut writer = RecordingWriter::new();

        let _ = fwrite_xattr_with(&info, &urls, CREDENTIALED, &mut writer);

        // user.mime_type carries the SERVER's Content-Type
        // (CURLINFO_CONTENT_TYPE), never a guess from the filename.
        assert_eq!(
            writer.value_of("user.mime_type"),
            Some(&b"text/html; charset=UTF-8"[..])
        );
        assert_eq!(
            writer.value_of("user.xdg.referrer.url"),
            Some(&b"https://referrer.example/"[..])
        );
    }

    #[test]
    fn the_origin_url_is_the_stripped_url() {
        let info = FakeInfo::both();
        let urls = FakeUrls::answering(STRIPPED);
        let mut writer = RecordingWriter::new();

        let _ = fwrite_xattr_with(&info, &urls, CREDENTIALED, &mut writer);

        // src/tool_xattr.c:125 -- the credentials must not reach the disk.
        assert_eq!(writer.value_of(ATTR_ORIGIN_URL), Some(STRIPPED.as_bytes()));
        assert_eq!(ATTR_ORIGIN_URL, "user.xdg.origin.url");
    }

    #[test]
    fn absent_metadata_skips_its_attribute_without_failing() {
        // src/tool_xattr.c:117 -- `if(!result && value)`. A failed getinfo and
        // a NULL value are the same thing: skip the row, do not fail.
        let info = FakeInfo::neither();
        let urls = FakeUrls::answering(STRIPPED);
        let mut writer = RecordingWriter::new();

        let got = fwrite_xattr_with(&info, &urls, CREDENTIALED, &mut writer);

        assert_eq!(got, Ok(()));
        assert_eq!(writer.names(), vec!["user.creator", "user.xdg.origin.url"]);
    }

    #[test]
    fn one_absent_value_does_not_suppress_the_other() {
        let info = FakeInfo {
            referer: None,
            content_type: Some(b"application/octet-stream".to_vec()),
        };
        let urls = FakeUrls::answering(STRIPPED);
        let mut writer = RecordingWriter::new();

        let got = fwrite_xattr_with(&info, &urls, CREDENTIALED, &mut writer);

        assert_eq!(got, Ok(()));
        assert_eq!(
            writer.names(),
            vec!["user.creator", "user.mime_type", "user.xdg.origin.url"]
        );
    }

    #[test]
    fn a_set_failure_stops_the_sequence_at_once() {
        // src/tool_xattr.c:114 -- `while(!err && ...)`. The second write is
        // the referrer, so refusing it must leave the mime type and the origin
        // URL unwritten.
        let info = FakeInfo::both();
        let urls = FakeUrls::answering(STRIPPED);
        let mut writer = RecordingWriter::refusing_call(2);

        let got = fwrite_xattr_with(&info, &urls, CREDENTIALED, &mut writer);

        // The refusal's errno survives the return, because
        // `src/tool_operate.c:637-638` interpolates it into the warning.
        assert_eq!(got, Err(XattrFailure::from_errno(REFUSAL_ERRNO)));
        assert_eq!(writer.names(), vec!["user.creator"]);
    }

    #[test]
    fn a_creator_failure_prevents_every_later_attribute() {
        // In C the creator write initialises `err` (:111), so failing it makes
        // the loop condition at :114 false and the guard at :121 false too.
        let info = FakeInfo::both();
        let urls = FakeUrls::answering(STRIPPED);
        let mut writer = RecordingWriter::refusing_call(1);

        let got = fwrite_xattr_with(&info, &urls, CREDENTIALED, &mut writer);

        assert_eq!(got, Err(XattrFailure::from_errno(REFUSAL_ERRNO)));
        assert_eq!(writer.names(), Vec::<&str>::new());
        // The URL was never touched either, because :121 is not reached.
        assert_eq!(urls.ops(), Vec::new());
    }

    #[test]
    fn a_third_row_failure_leaves_the_origin_url_unwritten() {
        let info = FakeInfo::both();
        let urls = FakeUrls::answering(STRIPPED);
        let mut writer = RecordingWriter::refusing_call(3);

        let got = fwrite_xattr_with(&info, &urls, CREDENTIALED, &mut writer);

        assert_eq!(got, Err(XattrFailure::from_errno(REFUSAL_ERRNO)));
        assert_eq!(
            writer.names(),
            vec!["user.creator", "user.xdg.referrer.url"]
        );
        assert_eq!(urls.ops(), Vec::new());
    }

    #[test]
    fn a_stripcredentials_failure_returns_an_error_and_writes_nothing_more() {
        // src/tool_xattr.c:123-124 -- `if(!nurl) return 1;`. Non-zero, and the
        // origin URL attribute is never written.
        let info = FakeInfo::both();
        let urls = FakeUrls::refusing(UrlRefusal::Get);
        let mut writer = RecordingWriter::new();

        let got = fwrite_xattr_with(&info, &urls, CREDENTIALED, &mut writer);

        // This route sets no errno, so the failure carries none -- C's warning
        // prints whatever stale value `errno` held, which is not a described
        // behaviour and is not invented here.
        assert_eq!(got, Err(XattrFailure::without_errno()));
        assert_eq!(
            writer.names(),
            vec!["user.creator", "user.xdg.referrer.url", "user.mime_type",]
        );
    }

    // The setting primitive, and the syscall behind it

    #[test]
    fn an_absent_value_is_a_no_op_that_reports_success() {
        // src/tool_xattr.c:82 -- `if(value)`. C leaves `err` at its :81
        // initialiser of 0 and writes nothing.
        let mut writer = RecordingWriter::new();

        let got = set_xattr(&mut writer, ATTR_CREATOR, None);

        assert_eq!(got, Ok(()));
        assert_eq!(writer.names(), Vec::<&str>::new());
    }

    #[test]
    fn a_present_value_reaches_the_writer_byte_for_byte() {
        let mut writer = RecordingWriter::new();

        let got = set_xattr(&mut writer, "user.mime_type", Some(&[0xff, 0x00]));

        assert_eq!(got, Ok(()));
        // Not text: CURLINFO_CONTENT_TYPE is server-chosen, so the bytes are
        // carried through unexamined.
        assert_eq!(writer.value_of("user.mime_type"), Some(&[0xff, 0x00][..]));
    }

    /// A descriptor on which `fsetxattr` is guaranteed to fail, and which the
    /// test creates for itself.
    ///
    /// `xattr(7)` restricts the `user.` namespace to regular files and
    /// directories, so a socket is refused -- measured here as `EPERM`. macOS
    /// keeps extended attributes in the file system and a socket has no file
    /// system behind it, so the refusal is `ENOTSUP` there. Both carry an
    /// `errno`, which is what these tests assert; neither number is written
    /// down, because the point is that whichever one the platform produced
    /// arrives intact.
    ///
    /// A socket pair rather than any path on disk, and that choice is load
    /// bearing three times over. A temporary file would make the outcome
    /// depend on whether the build host's file system carries extended
    /// attributes at all. A path under `/dev` would depend on the node still
    /// being the device it is supposed to be -- during this work `/dev/null`
    /// was, for a while, replaced by an ordinary file, which would have turned
    /// this assertion into a silent success *and* left an attribute behind on
    /// a real file. A bound socket, in turn, would need a port or a path that a
    /// parallel run could collide with. `UnixStream::pair` needs none of them:
    /// it is an anonymous pair of descriptors created and dropped inside the
    /// test.
    fn unattributable() -> std::os::unix::net::UnixStream {
        let (end, _other) = std::os::unix::net::UnixStream::pair()
            .expect("a socket pair needs no external resource");
        end
    }

    #[test]
    #[cfg_attr(miri, ignore = "fsetxattr(2) is a foreign function")]
    fn the_primitive_issues_the_syscall_and_reports_its_errno() {
        // The finding this closes: the body used to discard all three
        // arguments and return `Ok(())`, so `--xattr` wrote nothing and
        // reported nothing. A refusal proves the syscall is now reached --
        // a silent stub cannot produce an `errno`.
        let sock = unattributable();

        let got = set_file_xattr(sock.as_fd(), ATTR_CREATOR, b"curl");

        let failure = got.expect_err("a socket refuses user.* attributes");
        assert!(
            failure.errno().is_some(),
            "the errno must survive for src/tool_operate.c:637-638"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "fsetxattr(2) is a foreign function")]
    fn a_reported_errno_renders_without_the_rust_annotation() {
        // What the warning's `%s` interpolates. `curlx_strerror` yields the
        // bare system text, so the `(os error N)` that Rust appends must be
        // gone -- which is the shared helper's job, not this module's.
        let sock = unattributable();

        let failure = set_file_xattr(sock.as_fd(), ATTR_CREATOR, b"curl")
            .expect_err("a socket refuses user.* attributes");

        let text = failure
            .os_error_text()
            .expect("a syscall refusal always carries an errno");
        assert!(!text.is_empty());
        assert!(!text.contains("(os error"), "{text}");
    }

    #[test]
    fn a_failure_without_an_errno_renders_no_system_text() {
        // The `return 1` route at src/tool_xattr.c:124. There is no number to
        // render, and one is not invented.
        assert_eq!(XattrFailure::without_errno().errno(), None);
        assert_eq!(XattrFailure::without_errno().os_error_text(), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "fsetxattr(2) is a foreign function")]
    fn an_interior_nul_in_the_name_cannot_reach_the_syscall() {
        // The engine wrapper builds the C string the syscall needs, so a name
        // that cannot be one is refused with EINVAL before any call is made.
        // EINVAL is 22 on all four mandated targets, so the number is exact
        // here rather than probed. The attribute names in this module are
        // fixed ASCII literals, so this is a total-function guarantee rather
        // than a reachable path.
        let sock = unattributable();

        let got = set_file_xattr(sock.as_fd(), "user.\0creator", b"curl");

        assert_eq!(got, Err(XattrFailure::from_errno(22)));
    }

    #[test]
    #[cfg_attr(miri, ignore = "fsetxattr(2) is a foreign function")]
    fn the_production_path_reaches_the_real_syscall() {
        // src/tool_xattr.c:111 -- the creator write is first and
        // unconditional, so a descriptor that refuses attributes fails there
        // and the sequence stops, exactly as `!err` at :114 requires.
        //
        // This is the end-to-end assertion that `fwrite_xattr` wires
        // `FileXattrWriter` to the operating system: over the injected writer
        // the sequence tests above pass whatever the platform does, but this
        // one cannot.
        let info = FakeInfo::both();
        let urls = FakeUrls::answering(STRIPPED);
        let sock = unattributable();

        let got = fwrite_xattr(&info, &urls, CREDENTIALED, sock.as_fd());

        let failure = got.expect_err("a socket refuses user.* attributes");
        assert!(failure.errno().is_some());
        // src/tool_xattr.c:121 is not reached, so the URL is never touched.
        assert_eq!(urls.ops(), Vec::new());
    }

    #[test]
    fn the_diagnostic_binary_agrees_that_xattr_is_on() {
        // src/curlinfo.c:176-181 prints `xattr: ON` or `OFF` from
        // `#ifndef USE_XATTR`. Attributes are written now, so the diagnostic
        // binary must say ON, and this is the assertion that makes a future
        // disagreement between the two artifacts fail rather than mislead.
        //
        // `curlinfo` is a separate binary target, so its table cannot be
        // imported; the row is read from its source instead. The assertion is on
        // the constant the row is built from rather than on the rendered token,
        // because that constant is what decides the token.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../curl-rs/src/bin/curlinfo.rs"
        );
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            // Reachable when this file is compiled outside the workspace
            // layout; the assertion would then be about the harness.
            Err(_) => return,
        };
        let row = source
            .lines()
            .find(|line| line.contains("Capability::new(\"xattr: \""))
            .unwrap_or_default();
        // Either form decides ON on the mandated targets, and the row is
        // required to use one of them. `ALWAYS_COMPILED_IN` states it flatly;
        // `use_xattr()` derives it, conjoining the engine wrapper's presence
        // with the `linux`/`macos` `cfg` whose arms that wrapper compiles, so
        // it also reports OFF on a platform AAP 0.2.2 puts out of scope. The
        // derived form is what this tree carries, and it is the stronger of the
        // two; what the assertion forbids is a row that decides the question
        // some other way.
        assert!(
            row.contains("ALWAYS_COMPILED_IN") || row.contains("use_xattr()"),
            "curlinfo.rs must build the xattr row from ALWAYS_COMPILED_IN or \
             from the derived use_xattr() predicate now that attributes are \
             written, found: {row}"
        );
        assert!(
            !row.contains("NOT_DETERMINABLE") && !row.contains("NOT_PRESENT"),
            "the xattr row must no longer claim the capability is absent or \
             unknowable, found: {row}"
        );
    }

    // The error types are reportable

    #[test]
    fn both_failures_render_and_are_errors() {
        let xattr: &dyn std::error::Error = &XattrFailure::without_errno();
        let url: &dyn std::error::Error = &UrlApiFailure;

        assert_eq!(
            xattr.to_string(),
            "extended attribute metadata could not be recorded"
        );
        assert_eq!(url.to_string(), "URL API operation failed");
    }
}
