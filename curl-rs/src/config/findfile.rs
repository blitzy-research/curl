// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Locating a per-user dotfile -- `src/tool_findfile.c`.
//!
//! # It locates `.curlrc`, and it does not locate `.netrc`
//!
//! The first half is right and the second is not, and following it would be a
//! defect rather than a completion. `findfile` has exactly **two** call sites
//! in the whole C tool, and neither names `.netrc`:
//!
//! * `src/tool_parsecfg.c:92` -- `findfile(".curlrc", CURLRC_DOTSCORE)`,
//!   reached only when `parseconfig` was handed no filename, whose comment at
//!   `:91` reads "NULL means load .curlrc from homedir!". That caller becomes
//!   `curl-rs/src/config/parseconfig.rs`.
//! * `src/config2setopts.c:208` -- `findfile(".ssh/known_hosts", FALSE)`,
//!   reached only when the transfer is not `--insecure` and no known-hosts
//!   file was configured. That caller becomes
//!   `curl-rs/src/config/to_setopts.rs`.
//!
//! # The environment is a parameter, not an ambient read
//!
//! [`findfile_with`] takes the environment lookup and the password-database
//! home as arguments; [`findfile`] is the thin entry point that supplies both
//! from the live process. Two things follow, and both are deliberate:
//!
//! * The search is exercisable without mutating the process environment.
//!   `std::env::set_var` is process-global, so tests that set `HOME` would
//!   race each other under the default multi-threaded harness and would be
//!   flaky rather than wrong. Nothing below mutates the environment.
//! * Every path is resolved at **run time**, on every call. No environment
//!   value, home directory, user name or absolute path is captured at build
//!   time -- there is no `env!` or `option_env!` in this file -- because a
//!   baked-in value would make the binary non-reproducible and would also be
//!   wrong the moment the environment changed. This mirrors
//!   `curl-rs/src/cli/vars.rs:1276-1285`.
//!
//! # One gap, reported rather than worked around
//!
//! C's last resort reads the home directory from the password database
//! (`src/tool_findfile.c:139-148`). It cannot be implemented in this crate;
//! [`home_from_password_database`] carries the full account, and the
//! fallback's *position* and *semantics* are wired and tested regardless, so
//! that supplying the value later is a one-line change.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// `DIR_CHAR` -- `lib/curl_setup.h:684`.
///
/// A single byte rather than the C's one-character string literal, because it
/// is concatenated rather than interpolated. The Windows spelling `"\\"`
/// (`lib/curl_setup.h:664`) has no counterpart here: the four mandated targets
/// are `x86_64` and `aarch64` on Linux and macOS.
const DIR_CHAR: u8 = b'/';

/// The `'.'`-then-`'_'` prefixes of `checkhome` -- `src/tool_findfile.c:65`.
///
/// `const char pref[2] = { '.', '_' };`, in that order -- spelled as a byte
/// string because `clippy::byte_char_slices` rejects the element-wise form.
/// Which of the two is reached is decided by the probe count at `:67`; see
/// [`checkhome`].
const PREF: [u8; 2] = *b"._";

/// `CURLRC_DOTSCORE` -- `src/tool_findfile.h:28-32`.
#[allow(dead_code)]
pub(crate) const CURLRC_DOTSCORE: i32 = 1;

/// One row of the search table -- `struct finder`,
/// `src/tool_findfile.c:39-43`.
///
/// The field names are the C's. `append` is `Option<&str>` rather than a
/// possibly-empty string because C distinguishes `NULL` from a value
/// (`:116`), and `withoutdot` is the C's `bool`.
struct Finder {
    /// `const char *env` -- the environment variable to read.
    env: &'static str,
    /// `const char *append` -- suffixed to the raw value when present.
    append: Option<&'static str>,
    /// `bool withoutdot` -- probe the name with its leading dot removed.
    withoutdot: bool,
}

/// The search table -- `conf_list`, `src/tool_findfile.c:47-61`.
const CONF_LIST: [Finder; 5] = [
    // `{ "CURL_HOME", NULL, FALSE }` -- `:48`.
    Finder {
        env: "CURL_HOME",
        append: None,
        withoutdot: false,
    },
    // `{ "XDG_CONFIG_HOME", NULL, TRUE }` -- `:49`.
    Finder {
        env: "XDG_CONFIG_HOME",
        append: None,
        withoutdot: true,
    },
    // `{ "HOME", NULL, FALSE }` -- `:50`.
    Finder {
        env: "HOME",
        append: None,
        withoutdot: false,
    },
    // these are for .curlrc if XDG_CONFIG_HOME is not defined
    // (the C's comment, `:56`, kept with the two rows it explains)
    // `{ "CURL_HOME", "/.config", TRUE }` -- `:57`.
    Finder {
        env: "CURL_HOME",
        append: Some("/.config"),
        withoutdot: true,
    },
    // `{ "HOME", "/.config", TRUE }` -- `:58`.
    Finder {
        env: "HOME",
        append: Some("/.config"),
        withoutdot: true,
    },
];

/// Joins `home` and `name` with a single [`DIR_CHAR`].
///
/// This is the `curl_maprintf("%s" DIR_CHAR "%s", home, name)` of
/// `src/tool_findfile.c:70` and `:72`, performed on **bytes**.
///
/// It is a byte concatenation rather than [`PathBuf::push`] on purpose.
/// `push` replaces the base when handed a component that looks absolute, so
/// pushing the `"/.config"` of rows 3 and 4 onto `$HOME` would silently yield
/// `/.config` instead of `$HOME/.config`. Byte concatenation reproduces
/// `curl_maprintf` exactly and has no such special case.
fn join_under(home: &OsStr, name: &[u8]) -> PathBuf {
    let mut joined = Vec::with_capacity(
        home.as_bytes()
            .len()
            .saturating_add(name.len())
            .saturating_add(1),
    );
    joined.extend_from_slice(home.as_bytes());
    joined.push(DIR_CHAR);
    joined.extend_from_slice(name);
    PathBuf::from(OsString::from_vec(joined))
}

/// Reports whether `path` can be opened for reading.
fn opens(path: &Path) -> bool {
    File::open(path).is_ok()
}

/// Probes `fname` under `home` -- `checkhome`,
/// `src/tool_findfile.c:63-85`.
///
/// * `true` -- two candidates, `:67` and `:70`. The first byte of `fname` is
///   **replaced** by `'.'` and then by `'_'`, because the C interpolates
///   `pref[i]` followed by `&fname[1]`, which skips `fname[0]`. For
///   `.curlrc` that is `.curlrc` and then `_curlrc`.
/// * `false` -- one candidate, `:72`: `fname` verbatim under `home`.
fn checkhome(home: &OsStr, fname: &OsStr, dotscore: bool) -> Option<PathBuf> {
    // `for(i = 0; i < (dotscore ? 2 : 1); i++)` -- `:67`. Iterating the
    // prefix table itself keeps the count and the prefixes in step: taking
    // one element reaches only `'.'`, taking two reaches `'_'` as well.
    let probes = if dotscore { PREF.len() } else { 1 };

    for prefix in PREF.iter().take(probes) {
        let candidate = if dotscore {
            // `&fname[1]` -- everything after the first byte. `get` rather
            // than an index: a one-byte name leaves an empty tail, and a
            // slicing expression must not be able to panic. The split is on
            // bytes, not characters, because that is what the C pointer
            // arithmetic does.
            let tail = match fname.as_bytes().get(1..) {
                Some(rest) => rest,
                None => &[],
            };
            let mut name = Vec::with_capacity(tail.len().saturating_add(1));
            name.push(*prefix);
            name.extend_from_slice(tail);
            join_under(home, &name)
        } else {
            join_under(home, fname.as_bytes())
        };

        // `if(fd >= 0) { ... return path; }` -- `:75-80`.
        if opens(&candidate) {
            return Some(candidate);
        }
    }

    None
}

/// The home directory from the password database, when it can be obtained.
///
/// # This is a reported gap, not an implementation
///
/// C's last resort, `src/tool_findfile.c:139-148`, runs only after every
/// entry of [`CONF_LIST`] has missed:
///
/// ```c
/// #if defined(HAVE_GETPWUID) && defined(HAVE_GETEUID)
///   struct passwd *pw = getpwuid(geteuid());
///   if(pw) {
///     char *home = pw->pw_dir;
///     if(home && home[0])
///       return checkhome(home, fname, FALSE);
///   }
/// #endif
/// ```
///
/// `getpwuid` and `geteuid` are libc calls. There is no safe `std` API for
/// either, this crate is covered by `#![forbid(unsafe_code)]` and has no
/// `mod ffi` to exempt, and `curl-rs` does not depend on `libc` at all. So the
/// value cannot be produced here.
///
/// It cannot be borrowed from the engine either. The lookup belongs in
/// `curl-rs-lib/src/ffi/sys.rs`, the workspace's single sanctioned `unsafe`
/// island, and that module's public surface is closed: `curl-rs-lib` re-exports
/// exactly `disable_echo`, `local_utc_offset_secs`, `set_file_xattr`,
/// `set_locale_from_environment`, `strftime_gmt`, `terminal_columns` and
/// `EchoGuard` (`curl-rs-lib/src/lib.rs:1417-1420`). A password-database
/// lookup is not among them -- `effective_uid` exists but is `pub(crate)` to
/// that crate, and no `getpwuid` wrapper exists anywhere in it. Resolving
/// this therefore needs a decision in the engine, not a local workaround.
///
/// # What is *not* deferred
///
/// Two substitutions are specifically **not** made here, because each would
/// change behaviour while appearing to fix it:
///
/// * `std::env::var_os("HOME")` -- already `CONF_LIST[2]`, so this would be
///   dead code in every case except the one the fallback exists to serve,
///   namely `HOME` being unset.
fn home_from_password_database() -> Option<OsString> {
    None
}

/// Walks [`CONF_LIST`] with the environment and the password-database home
/// supplied by the caller -- the body of `findfile`,
/// `src/tool_findfile.c:98-150`.
///
/// # Preconditions
///
/// C asserts two things in debug builds at `:101-102`:
/// `DEBUGASSERT(fname && fname[0])` and
/// `DEBUGASSERT((dotscore != 1) || (fname[0] == '.'))`. `DEBUGBUILD` is not a
/// Cargo feature, so neither becomes a runtime check here -- an `assert!` on
/// caller input would introduce a panic the C never had. They are documented
/// instead:
///
/// * `fname` is expected to be non-empty. An empty name is nonetheless handled
///   rather than assumed away, because `:104-105` guards it in *all* builds.
/// * when `dotscore == 1`, `fname`'s first byte is expected to be `'.'`. The
///   sole caller that passes `1` passes `".curlrc"`
///   (`src/tool_parsecfg.c:92`). Nothing here enforces it; a name that
///   violates it simply has its first byte replaced, which is what the C does.
fn findfile_with<F>(
    fname: &OsStr,
    dotscore: i32,
    getenv: F,
    passwd_home: Option<&OsStr>,
) -> Option<PathBuf>
where
    F: Fn(&'static str) -> Option<OsString>,
{
    // `if(!fname[0]) return NULL;` -- `:104-105`. This runs in every build,
    // unlike the assertions above it.
    if fname.as_bytes().is_empty() {
        return None;
    }

    // QUIRK A, part one -- `:98` and `:131`. `dotscore` is C's *function
    // parameter*, and `:131` assigns to it from inside the loop, so the
    // assignment survives into every later iteration. Holding it as a mutable
    // local of an integer type reproduces that; a `bool`, or a value
    // recomputed per iteration, would not.
    let mut dotscore = dotscore;

    // `for(i = 0; conf_list[i].env; i++)` -- `:107`.
    for entry in &CONF_LIST {
        // `char *home = curl_getenv(conf_list[i].env); if(home) {` --
        // `:108-109`. An unset variable skips the entry entirely.
        let value = match getenv(entry.env) {
            Some(value) => value,
            None => continue,
        };

        // `const char *filename = fname;` -- `:111`. Declared *inside* the
        // loop, so each entry starts from the original name however the
        // previous entry adjusted its own copy. Only `dotscore` carries over.
        let mut filename = fname.as_bytes();

        // `if(!home[0]) { curl_free(home); continue; }` -- `:112-115`. An
        // empty value is skipped, and the order matters: the emptiness test
        // precedes the append at `:116`, so `HOME=""` is rejected outright
        // rather than becoming the current directory or a bare `/.config`.
        if value.as_bytes().is_empty() {
            continue;
        }

        // `curl_maprintf("%s%s", home, conf_list[i].append)` -- `:116-122`.
        // The suffix joins the raw value with no separator of its own: the
        // table already carries the leading `/` of `"/.config"`.
        let mut home = value.as_bytes().to_vec();
        if let Some(append) = entry.append {
            home.extend_from_slice(append.as_bytes());
        }

        // `if(conf_list[i].withoutdot)` -- `:123-132`.
        if entry.withoutdot {
            if dotscore == 0 {
                // this is not looking for .curlrc, or the XDG_CONFIG_HOME was
                // defined so we skip the extended check
                // (the C's comment, `:125-126`)
                continue;
            }

            // `filename++;` -- `:130`, "move past the leading dot". Byte
            // arithmetic, so it is done on bytes; `get` keeps it panic-free
            // for a one-byte name, which yields an empty name exactly as the
            // C pointer would.
            filename = match filename.get(1..) {
                Some(rest) => rest,
                None => &[],
            };

            // QUIRK A, part two -- `:131`, "disable it for this check". The
            // consequence is that AT MOST ONE `withoutdot` entry is ever
            // tried per call: once this fires, the `dotscore == 0` test above
            // skips every later `withoutdot` row. So a set, non-empty
            // `XDG_CONFIG_HOME` (entry 1) suppresses entries 3 and 4
            // outright, and entry 2 is then probed with `dotscore == 0`.
            dotscore = 0;
        }

        // `checkhome(home, filename, dotscore ? dotscore - 1 : 0)` -- `:133`.
        //
        // QUIRK B -- the decrement is reproduced rather than folded away.
        // `CURLRC_DOTSCORE` is 1 on every mandated target, so `dotscore - 1`
        // is 0, `checkhome` takes its single-candidate branch, and the
        // `_curlrc` variant NEVER fires on Linux or macOS; it fires only where
        // the constant is 2, which is Windows (`src/tool_findfile.h:29`).
        // Simplifying this to a boolean would be correct today and would
        // silently diverge if the constant ever changed, so the arithmetic
        // stays. C then narrows the `int` to `checkhome`'s `bool` parameter,
        // where any non-zero value is true; `!= 0` is that conversion.
        let probe = if dotscore != 0 { dotscore - 1 } else { 0 };
        let path = checkhome(
            OsStr::from_bytes(&home),
            OsStr::from_bytes(filename),
            probe != 0,
        );

        // `if(path) return path;` -- `:135-136`. The first entry that yields a
        // readable file wins; a miss falls through to the next entry.
        if path.is_some() {
            return path;
        }
    }

    // `:139-148`, reached only when every entry above missed. C tests both
    // `pw` and `pw_dir[0]`, so an absent lookup and an empty home behave
    // alike, and it hands `checkhome` the **original** `fname` -- dot intact,
    // never the `filename` the loop advanced -- together with `FALSE` rather
    // than the caller's `dotscore`. C returns this result directly at `:145`,
    // so a miss here is the `NULL` of `:149`.
    match passwd_home {
        Some(home) if !home.as_bytes().is_empty() => {
            checkhome(home, fname, false)
        }
        _ => None,
    }
}

/// Returns the full path of `fname` found under one of the user's home
/// locations, or `None` -- `findfile`, `src/tool_findfile.c:98-150`.
///
/// The returned path is owned. C returns heap memory the caller must release
/// with `curl_free` (`:88-89`); ownership makes that release automatic, so
/// neither caller needs the `curl_free` that `src/tool_parsecfg.c:97` and
/// `src/config2setopts.c:214` perform.
#[allow(dead_code)]
pub(crate) fn findfile(fname: &OsStr, dotscore: i32) -> Option<PathBuf> {
    // Read now, not at build time, and never cached: see the module
    // documentation. `var_os` rather than `var` because an environment value
    // is arbitrary bytes on the mandated targets and `var` would reject a
    // usable non-UTF-8 home, turning a hit into a miss.
    let passwd_home = home_from_password_database();
    findfile_with(fname, dotscore, std::env::var_os, passwd_home.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::TempDir;

    /// Builds a `getenv` from explicit pairs; any name absent from `pairs` is
    /// unset.
    fn lookup(
        pairs: &[(&'static str, &OsStr)],
    ) -> impl Fn(&'static str) -> Option<OsString> {
        let owned: Vec<(&'static str, OsString)> = pairs
            .iter()
            .map(|(name, value)| (*name, (*value).to_os_string()))
            .collect();
        move |name| {
            owned
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        }
    }

    /// Creates an empty, readable file, making any parent directory first.
    fn touch(path: &Path) -> io::Result<PathBuf> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, b"")?;
        Ok(path.to_path_buf())
    }

    #[test]
    fn the_search_table_matches_the_c_declaration_order() {
        // `conf_list`, `src/tool_findfile.c:47-61`, minus the three `#ifdef
        // _WIN32` rows at `:51-55`. The C line for each surviving row is named
        // beside it.
        let expected: [(&str, Option<&str>, bool); 5] = [
            ("CURL_HOME", None, false),            // :48
            ("XDG_CONFIG_HOME", None, true),       // :49
            ("HOME", None, false),                 // :50
            ("CURL_HOME", Some("/.config"), true), // :57
            ("HOME", Some("/.config"), true),      // :58
        ];

        assert_eq!(
            CONF_LIST.len(),
            expected.len(),
            "the table must hold exactly the five in-scope rows"
        );
        for (row, (env, append, withoutdot)) in
            CONF_LIST.iter().zip(expected.iter())
        {
            assert_eq!(row.env, *env);
            assert_eq!(row.append, *append);
            assert_eq!(row.withoutdot, *withoutdot);
        }

        // Stated independently of the loop, because which rows carry the flag
        // is what drives both quirks: indices 1, 3 and 4, and no others.
        let flagged: Vec<usize> = CONF_LIST
            .iter()
            .enumerate()
            .filter(|(_, row)| row.withoutdot)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(flagged, vec![1, 3, 4]);

        // No Windows-only row leaked in.
        assert!(CONF_LIST
            .iter()
            .all(|row| row.env != "USERPROFILE" && row.env != "APPDATA"));

        // `src/tool_findfile.h:31` and `lib/curl_setup.h:684`.
        assert_eq!(CURLRC_DOTSCORE, 1);
        assert_eq!(DIR_CHAR, b'/');
        assert_eq!(PREF, *b"._");
    }

    #[test]
    fn an_unset_variable_is_skipped() -> io::Result<()> {
        // `if(home)` -- `src/tool_findfile.c:109`. `CURL_HOME` and
        // `XDG_CONFIG_HOME` are absent, so the search reaches `HOME`.
        let home = TempDir::new()?;
        let target = touch(&home.path().join(".curlrc"))?;

        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[("HOME", home.path().as_os_str())]),
            None,
        );

        assert_eq!(found.as_deref(), Some(target.as_path()));
        Ok(())
    }

    #[test]
    fn an_empty_value_is_skipped_and_never_means_the_current_directory(
    ) -> io::Result<()> {
        // `if(!home[0]) { curl_free(home); continue; }` -- `:112-115`, which
        // runs BEFORE the append at `:116`, so an empty value can neither
        // become the current directory nor produce a bare `/.config`.
        let home = TempDir::new()?;
        let target = touch(&home.path().join(".curlrc"))?;

        // An empty `CURL_HOME` neither matches nor aborts the search: the
        // later `HOME` entry still answers.
        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[
                ("CURL_HOME", OsStr::new("")),
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );
        assert_eq!(found.as_deref(), Some(target.as_path()));

        // And on its own an empty value yields nothing, rather than resolving
        // relative to wherever the process happens to be running.
        let alone = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[("HOME", OsStr::new(""))]),
            None,
        );
        assert_eq!(alone, None);
        Ok(())
    }

    #[test]
    fn an_empty_value_is_skipped_before_the_withoutdot_row() -> io::Result<()> {
        // The two assertions above cannot tell a skipped entry from one that
        // probed `/.curlrc` and missed, because a test cannot create a file at
        // the filesystem root. This one can, and it pins the STATEMENT ORDER:
        // `:112-115` returns to the top of the loop before `:123` is reached,
        // so an empty value never reaches the `withoutdot` branch and therefore
        // never clears `dotscore`.
        let home = TempDir::new()?;
        let target = touch(&home.path().join(".config").join("curlrc"))?;

        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[
                ("XDG_CONFIG_HOME", OsStr::new("")),
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );

        assert_eq!(
            found.as_deref(),
            Some(target.as_path()),
            "an empty value must not consume the withoutdot allowance"
        );

        // Control: set NON-empty, the very same row does consume it, and the
        // same file becomes unreachable. Only the emptiness of the value
        // differs between the two calls.
        let xdg = TempDir::new()?;
        let suppressed = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[
                ("XDG_CONFIG_HOME", xdg.path().as_os_str()),
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );
        assert_eq!(suppressed, None);
        Ok(())
    }

    #[test]
    fn the_first_matching_entry_wins() -> io::Result<()> {
        // `if(path) return path;` -- `:135-136`. `CURL_HOME` is row 0 and
        // `HOME` is row 2, so `CURL_HOME` answers even though both match.
        let curl_home = TempDir::new()?;
        let home = TempDir::new()?;
        let preferred = touch(&curl_home.path().join(".curlrc"))?;
        touch(&home.path().join(".curlrc"))?;

        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[
                ("CURL_HOME", curl_home.path().as_os_str()),
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );

        assert_eq!(found.as_deref(), Some(preferred.as_path()));
        Ok(())
    }

    #[test]
    fn the_probe_is_an_open_and_not_an_existence_test() -> io::Result<()> {
        // `curlx_open(c, O_RDONLY)` accepted on `fd >= 0` -- `:74-75`. The
        // distinction from `Path::exists` is demonstrated with a UNIX-domain
        // socket, because that is the case where the two answers differ for
        // EVERY user: the directory entry is there, so `exists` reports true,
        // while `open(2)` fails with `ENXIO`. The permission case below is the
        // one users actually hit, but it cannot be asserted as root, so this
        // case carries the invariant unconditionally.
        let curl_home = TempDir::new()?;
        let home = TempDir::new()?;

        let socket_path = curl_home.path().join(".curlrc");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
        assert!(
            socket_path.exists(),
            "the socket must be present for the comparison to mean anything"
        );
        assert!(!opens(&socket_path), "open(2) must reject a socket");

        let readable = touch(&home.path().join(".curlrc"))?;

        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[
                ("CURL_HOME", curl_home.path().as_os_str()),
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );

        // The socket EXISTS and sits in the earlier row, so an existence test
        // would have returned it. The open fails, so the search continues.
        assert_eq!(found.as_deref(), Some(readable.as_path()));
        Ok(())
    }

    #[test]
    fn an_unreadable_file_is_not_a_match() -> io::Result<()> {
        // The same `:74-75` invariant in the form users meet it: a `.curlrc`
        // whose mode denies reading is skipped rather than loaded.
        let curl_home = TempDir::new()?;
        let home = TempDir::new()?;

        let unreadable = touch(&curl_home.path().join(".curlrc"))?;
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000))?;

        // Skipped where the mode cannot be enforced -- running as root, or a
        // filesystem that ignores permission bits. Detected by attempting the
        // open rather than by querying the effective user id, which would need
        // a libc call this crate cannot make. The socket case above keeps the
        // invariant covered when this returns early.
        if opens(&unreadable) {
            return Ok(());
        }

        let readable = touch(&home.path().join(".curlrc"))?;

        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[
                ("CURL_HOME", curl_home.path().as_os_str()),
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );

        assert_eq!(found.as_deref(), Some(readable.as_path()));
        Ok(())
    }

    #[test]
    fn a_dangling_symlink_is_not_a_match() -> io::Result<()> {
        // `:74-75` again. Note that `Path::exists` also reports false here,
        // because it follows the link -- so unlike the socket above, this case
        // does not distinguish the two probes. What it does cover is that a
        // present directory entry whose open fails is a miss that the search
        // walks past rather than an error that ends it.
        let curl_home = TempDir::new()?;
        let home = TempDir::new()?;

        symlink(
            curl_home.path().join("no-such-target"),
            curl_home.path().join(".curlrc"),
        )?;
        let readable = touch(&home.path().join(".curlrc"))?;

        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[
                ("CURL_HOME", curl_home.path().as_os_str()),
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );

        assert_eq!(found.as_deref(), Some(readable.as_path()));
        Ok(())
    }

    #[test]
    fn the_dotless_name_is_probed_under_xdg_config_home() -> io::Result<()> {
        // Row 1 is `withoutdot`, so `filename++` at `:130` drops the dot and
        // the name probed under `XDG_CONFIG_HOME` is `curlrc`.
        let xdg = TempDir::new()?;
        let target = touch(&xdg.path().join("curlrc"))?;

        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[("XDG_CONFIG_HOME", xdg.path().as_os_str())]),
            None,
        );
        assert_eq!(found.as_deref(), Some(target.as_path()));

        // The dotted name is NOT what is looked for there: a `.curlrc` in the
        // same directory does not answer for row 1.
        let other = TempDir::new()?;
        touch(&other.path().join(".curlrc"))?;
        let missed = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[("XDG_CONFIG_HOME", other.path().as_os_str())]),
            None,
        );
        assert_eq!(missed, None);
        Ok(())
    }

    #[test]
    fn the_name_resets_for_every_row_even_after_one_advanced_it(
    ) -> io::Result<()> {
        // `const char *filename = fname;` -- `:111`, declared INSIDE the loop
        // and therefore reset on every iteration. Row 1 is `withoutdot` and
        // advances its own copy past the dot (`:130`); row 2 must nonetheless
        // probe the DOTTED name.
        //
        // Only `dotscore` carries across rows. Hoisting `filename` beside it
        // would make row 2 look for `curlrc` under `$HOME` and miss the
        // `.curlrc` that is actually there -- a divergence neither Quirk A test
        // can see, because there both rows miss either way.
        let xdg = TempDir::new()?;
        let home = TempDir::new()?;
        let target = touch(&home.path().join(".curlrc"))?;

        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[
                // Set and non-empty, so row 1 fires and advances its copy...
                ("XDG_CONFIG_HOME", xdg.path().as_os_str()),
                // ...and row 2 must still find the dotted name here.
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );

        assert_eq!(
            found.as_deref(),
            Some(target.as_path()),
            "row 2 must probe `.curlrc`, not the name row 1 advanced"
        );
        Ok(())
    }

    #[test]
    fn quirk_a_a_set_xdg_config_home_suppresses_both_config_rows(
    ) -> io::Result<()> {
        // `dotscore = 0;` -- `:131`, "disable it for this check". Row 1 fires
        // and clears `dotscore`, so rows 3 and 4 hit the `!dotscore` guard at
        // `:124` and are skipped even though both hold a match.
        //
        // Only the presence of `XDG_CONFIG_HOME` differs between the two calls
        // below; the filesystem is identical, and the outcome flips.
        let xdg = TempDir::new()?;
        let curl_home = TempDir::new()?;
        let home = TempDir::new()?;

        let via_curl_home =
            touch(&curl_home.path().join(".config").join("curlrc"))?;
        touch(&home.path().join(".config").join("curlrc"))?;

        let suppressed = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[
                ("XDG_CONFIG_HOME", xdg.path().as_os_str()),
                ("CURL_HOME", curl_home.path().as_os_str()),
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );
        assert_eq!(
            suppressed, None,
            "rows 3 and 4 must be unreachable once row 1 has fired"
        );

        // Control: with `XDG_CONFIG_HOME` unset, row 3 is the first
        // `withoutdot` row reached and the same file is found.
        let reached = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[
                ("CURL_HOME", curl_home.path().as_os_str()),
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );
        assert_eq!(reached.as_deref(), Some(via_curl_home.as_path()));
        Ok(())
    }

    #[test]
    fn quirk_a_at_most_one_withoutdot_row_is_tried_per_call() -> io::Result<()>
    {
        // The sharpest form of `:131`. Row 3 is reached, MISSES, and has
        // already cleared `dotscore` -- so row 4 is skipped even though it
        // holds a match. A boolean that were recomputed per row, or reset
        // after a miss, would find the file and diverge from the C.
        let curl_home = TempDir::new()?;
        let home = TempDir::new()?;

        // Row 3's directory exists but holds nothing.
        fs::create_dir_all(curl_home.path().join(".config"))?;
        // Row 4's directory holds a match.
        let via_home = touch(&home.path().join(".config").join("curlrc"))?;

        let suppressed = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[
                ("CURL_HOME", curl_home.path().as_os_str()),
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );
        assert_eq!(
            suppressed, None,
            "row 4 must be unreachable once row 3 has fired and missed"
        );

        // Control: with `CURL_HOME` unset, row 4 becomes the first
        // `withoutdot` row reached and the very same file is found.
        let reached = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[("HOME", home.path().as_os_str())]),
            None,
        );
        assert_eq!(reached.as_deref(), Some(via_home.as_path()));
        Ok(())
    }

    #[test]
    fn quirk_b_the_underscore_variant_never_fires_on_this_platform(
    ) -> io::Result<()> {
        // `checkhome(home, filename, dotscore ? dotscore - 1 : 0)` -- `:133`.
        // `CURLRC_DOTSCORE` is 1 here, so the argument is 0 and `checkhome`
        // takes its single-candidate branch.
        let home = TempDir::new()?;
        touch(&home.path().join("_curlrc"))?;

        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[("HOME", home.path().as_os_str())]),
            None,
        );
        assert_eq!(
            found, None,
            "`_curlrc` must not be found where CURLRC_DOTSCORE is 1"
        );

        // The branch itself is present and correct -- it is the arithmetic,
        // not a missing implementation, that withholds it. Asked directly,
        // `checkhome` probes `.curlrc` and then `_curlrc`, which is what the
        // Windows constant of 2 (`src/tool_findfile.h:29`) would reach.
        let underscore =
            checkhome(home.path().as_os_str(), OsStr::new(".curlrc"), true);
        assert_eq!(underscore, Some(home.path().join("_curlrc")));

        // And the dotted name still wins when both exist, because `'.'` is
        // `PREF[0]` (`:65`).
        let dotted = touch(&home.path().join(".curlrc"))?;
        let ordered =
            checkhome(home.path().as_os_str(), OsStr::new(".curlrc"), true);
        assert_eq!(ordered.as_deref(), Some(dotted.as_path()));
        Ok(())
    }

    #[test]
    fn the_config_suffix_is_appended_and_does_not_replace_the_home(
    ) -> io::Result<()> {
        // `curl_maprintf("%s%s", home, conf_list[i].append)` -- `:117`.
        // `PathBuf::push("/.config")` would discard the base and probe
        // `/.config/curlrc`; byte concatenation keeps `$HOME/.config/curlrc`.
        let home = TempDir::new()?;
        let target = touch(&home.path().join(".config").join("curlrc"))?;

        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[("HOME", home.path().as_os_str())]),
            None,
        );
        assert_eq!(found.as_deref(), Some(target.as_path()));

        // Stated separately: the hit is under the temporary home, not at the
        // filesystem root.
        let under_home = match &found {
            Some(path) => path.starts_with(home.path()),
            None => false,
        };
        assert!(under_home, "the appended suffix must not replace the base");
        Ok(())
    }

    #[test]
    fn a_nested_relative_name_resolves_verbatim_when_dotscore_is_zero(
    ) -> io::Result<()> {
        // The `src/config2setopts.c:208` call shape:
        // `findfile(".ssh/known_hosts", FALSE)`. `dotscore` is 0, so every
        // `withoutdot` row is skipped at `:124` and the name is never split.
        let curl_home = TempDir::new()?;
        let home = TempDir::new()?;

        let via_home = touch(&home.path().join(".ssh").join("known_hosts"))?;
        let found = findfile_with(
            OsStr::new(".ssh/known_hosts"),
            0,
            lookup(&[("HOME", home.path().as_os_str())]),
            None,
        );
        assert_eq!(found.as_deref(), Some(via_home.as_path()));

        // `CURL_HOME` still precedes `HOME` for a nested name.
        let preferred =
            touch(&curl_home.path().join(".ssh").join("known_hosts"))?;
        let found = findfile_with(
            OsStr::new(".ssh/known_hosts"),
            0,
            lookup(&[
                ("CURL_HOME", curl_home.path().as_os_str()),
                ("HOME", home.path().as_os_str()),
            ]),
            None,
        );
        assert_eq!(found.as_deref(), Some(preferred.as_path()));

        // And a `dotscore` of 0 never consults a `/.config` directory, so a
        // known-hosts file placed there is not trust material curl would load.
        let xdg = TempDir::new()?;
        let config_only = TempDir::new()?;
        touch(
            &config_only
                .path()
                .join(".config")
                .join(".ssh")
                .join("known_hosts"),
        )?;
        let missed = findfile_with(
            OsStr::new(".ssh/known_hosts"),
            0,
            lookup(&[
                ("XDG_CONFIG_HOME", xdg.path().as_os_str()),
                ("HOME", config_only.path().as_os_str()),
            ]),
            None,
        );
        assert_eq!(missed, None);
        Ok(())
    }

    #[test]
    fn an_empty_name_returns_none_without_panicking() -> io::Result<()> {
        // `if(!fname[0]) return NULL;` -- `:104-105`. The guard precedes both
        // the loop and the password-database fallback, so a matching file and
        // a usable fallback home change nothing.
        let home = TempDir::new()?;
        touch(&home.path().join(".curlrc"))?;

        let found = findfile_with(
            OsStr::new(""),
            CURLRC_DOTSCORE,
            lookup(&[("HOME", home.path().as_os_str())]),
            Some(home.path().as_os_str()),
        );

        assert_eq!(found, None);
        Ok(())
    }

    #[test]
    fn non_utf8_values_and_names_survive_without_loss() -> io::Result<()> {
        // An environment value and a file name are arbitrary byte strings on
        // the mandated targets. `var_os` and byte concatenation preserve them;
        // `var`, or a round trip through `str`, would reject or mangle them.
        let parent = TempDir::new()?;
        let home = parent.path().join(OsString::from_vec(b"h\xFFme".to_vec()));
        fs::create_dir(&home)?;

        let name = OsString::from_vec(b".curlrc\xFE".to_vec());
        let target = touch(&home.join(&name))?;

        let found = findfile_with(
            &name,
            0,
            lookup(&[("HOME", home.as_os_str())]),
            None,
        );
        assert_eq!(found.as_deref(), Some(target.as_path()));

        // Both invalid bytes survived: nothing was replaced by U+FFFD.
        let recovered = match found {
            Some(path) => path.into_os_string().into_vec(),
            None => Vec::new(),
        };
        assert!(recovered.ends_with(b"\xFE"), "the name was altered");
        assert!(
            recovered.windows(4).any(|window| window == b"h\xFFme"),
            "the home directory was altered"
        );
        Ok(())
    }

    #[test]
    fn the_leading_byte_is_dropped_on_bytes_not_chars() -> io::Result<()> {
        // `filename++` at `:130` advances exactly one BYTE. With a name whose
        // remainder is multi-byte UTF-8, dropping a `char` instead would
        // remove the wrong amount; the probe below only succeeds if precisely
        // one byte was removed.
        let xdg = TempDir::new()?;
        let name = OsString::from_vec(b".\xC3\xA9rc".to_vec());
        let target = touch(
            &xdg.path().join(OsString::from_vec(b"\xC3\xA9rc".to_vec())),
        )?;

        let found = findfile_with(
            &name,
            CURLRC_DOTSCORE,
            lookup(&[("XDG_CONFIG_HOME", xdg.path().as_os_str())]),
            None,
        );

        assert_eq!(found.as_deref(), Some(target.as_path()));
        Ok(())
    }

    #[test]
    fn a_one_byte_name_does_not_panic() -> io::Result<()> {
        // `filename++` on a one-byte name leaves an empty name, and
        // `&fname[1]` an empty tail. Both are reachable and neither may panic;
        // `get(1..)` is what guarantees that.
        let xdg = TempDir::new()?;
        let home = TempDir::new()?;

        let stripped = findfile_with(
            OsStr::new("."),
            CURLRC_DOTSCORE,
            lookup(&[("XDG_CONFIG_HOME", xdg.path().as_os_str())]),
            None,
        );
        // `$XDG/` names the directory itself, which `open(2)` accepts on the
        // mandated targets, so C finds it here too. What is asserted is that
        // the empty name is handled at all, and that nothing outside the
        // requested home is returned.
        let inside = match &stripped {
            Some(path) => path.starts_with(xdg.path()),
            None => true,
        };
        assert!(inside);

        // The dotscore branch of `checkhome` is the other one-byte path.
        let probed = checkhome(home.path().as_os_str(), OsStr::new("."), true);
        let inside = match &probed {
            Some(path) => path.starts_with(home.path()),
            None => true,
        };
        assert!(inside);
        Ok(())
    }

    #[test]
    fn the_password_database_seam_yields_nothing_today() {
        // The reported gap. `src/tool_findfile.c:139-148` needs
        // `getpwuid(geteuid())`, which this crate cannot call without `unsafe`
        // or a new dependency, and which `curl-rs-lib` does not expose. See
        // `home_from_password_database` for the full account.
        assert_eq!(home_from_password_database(), None);

        // The consequence, stated so it is not mistaken for a passing search:
        // with no variable set, the live entry point can find nothing at all.
        assert_eq!(
            findfile_with(
                OsStr::new(".curlrc"),
                CURLRC_DOTSCORE,
                lookup(&[]),
                home_from_password_database().as_deref(),
            ),
            None
        );
    }

    #[test]
    fn the_password_database_fallback_runs_only_after_every_row_missed(
    ) -> io::Result<()> {
        // `:139` sits after the loop, so the fallback is the last resort. The
        // ordering is asserted here so that supplying the value later slots in
        // at the right point rather than ahead of the environment.
        let home = TempDir::new()?;
        let passwd = TempDir::new()?;
        let via_home = touch(&home.path().join(".curlrc"))?;
        let via_passwd = touch(&passwd.path().join(".curlrc"))?;

        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[("HOME", home.path().as_os_str())]),
            Some(passwd.path().as_os_str()),
        );
        assert_eq!(
            found.as_deref(),
            Some(via_home.as_path()),
            "an environment hit must win over the password database"
        );

        // With nothing set, the fallback answers.
        let fallback = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[]),
            Some(passwd.path().as_os_str()),
        );
        assert_eq!(fallback.as_deref(), Some(via_passwd.as_path()));

        // `if(home && home[0])` -- `:144`. An empty home is ignored.
        let empty = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[]),
            Some(OsStr::new("")),
        );
        assert_eq!(empty, None);
        Ok(())
    }

    #[test]
    fn the_password_database_fallback_uses_the_original_name_and_no_dotscore(
    ) -> io::Result<()> {
        // `return checkhome(home, fname, FALSE);` -- `:145`. It passes the
        // ORIGINAL `fname`, not the `filename` the loop advanced, and `FALSE`
        // rather than the caller's `dotscore`.
        let xdg = TempDir::new()?;
        let passwd = TempDir::new()?;

        // Row 1 fires and misses, which advances its own copy of the name and
        // clears `dotscore` -- neither of which may affect the fallback.
        // The dotless name would match if `filename` were reused...
        touch(&passwd.path().join("curlrc"))?;
        // ...and the underscore name would match if `dotscore` were forwarded.
        touch(&passwd.path().join("_curlrc"))?;

        let neither = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[("XDG_CONFIG_HOME", xdg.path().as_os_str())]),
            Some(passwd.path().as_os_str()),
        );
        assert_eq!(
            neither, None,
            "the fallback must probe only the dot-intact name"
        );

        // The dot-intact name is what it looks for.
        let dotted = touch(&passwd.path().join(".curlrc"))?;
        let found = findfile_with(
            OsStr::new(".curlrc"),
            CURLRC_DOTSCORE,
            lookup(&[("XDG_CONFIG_HOME", xdg.path().as_os_str())]),
            Some(passwd.path().as_os_str()),
        );
        assert_eq!(found.as_deref(), Some(dotted.as_path()));
        Ok(())
    }

    #[test]
    fn the_entry_point_resolves_at_run_time_and_mutates_nothing() {
        // Not an assertion about whoever runs the suite -- there may or may not
        // be a `.curlrc` in their home. What is asserted is that the live entry
        // point runs, reads the environment at call time, and leaves it exactly
        // as it found it, which is what keeps the rest of this module hermetic.
        let before = (
            std::env::var_os("HOME"),
            std::env::var_os("CURL_HOME"),
            std::env::var_os("XDG_CONFIG_HOME"),
        );

        let found = findfile(OsStr::new(".curlrc"), CURLRC_DOTSCORE);

        // Whatever it found is absolute-or-relative exactly as the variable
        // was, and it opened: re-probing it agrees with the search.
        if let Some(path) = found.as_deref() {
            assert!(opens(path));
        }

        assert_eq!(
            (
                std::env::var_os("HOME"),
                std::env::var_os("CURL_HOME"),
                std::env::var_os("XDG_CONFIG_HOME"),
            ),
            before,
            "the search must not mutate the process environment"
        );
    }
}
