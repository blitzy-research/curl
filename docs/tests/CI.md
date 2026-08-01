<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Continuous Integration for curl

curl runs in many different environments, so every change is run against a
large number of test suites.

Every pull request is verified for each of the following. This first list
covers the retained C build:

- it still builds, warning-free, on Linux, macOS, Windows, BSDs, with both
  clang and gcc, autotools and cmake, out-of-tree and in-tree.
- it still builds fine on Windows with all supported MSVC versions
- it follows rudimentary code style rules
- the release tarball (the "dist") still works
- different TLS backends and options still compile and pass tests

The last item stays on this list and is not superseded. The C tree is retained
as the reference oracle for the migration, and its matrices in `linux.yml`,
`macos.yml`, `windows.yml` and `http3-linux.yml` still exercise OpenSSL,
GnuTLS, wolfSSL, mbedTLS, Schannel, rustls-ffi and MultiSSL. That is a
statement about the retained C build only. The single-rustls rule in the next
section governs the `Rust` target, and the two do not conflict, because they
describe two different artifacts.

The release-tarball item there is specific to Autotools packaging. In the
specified target design that distribution check is replaced rather than
carried forward, because a `Cargo` `workspace` has no Autotools distribution
tarball to package.

The specified `Rust` target is verified for the following. All nine of the
specified workflow files are on disk in this checkout, so every item below is
backed by a workflow that is committed. That is not the same as an item that
passes today: several of those gates guard parts of the target design that have
not been built yet, and each says so where it is listed. The
[Specified Rust workflows](#specified-rust-workflows) section records the full
inventory and the status of each gate:

- the release build of the whole `workspace` is warning-free on each of the
  four specified targets `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` and
  `aarch64-apple-darwin`, all four of which are 64-bit.
- `Rust` code is checked with `cargo clippy --workspace -- -D warnings` and
  formatted with `rustfmt`, in place of the `checksrc` pass that covers the C
  sources. Promoting warnings to errors makes a single lint finding a merge
  blocker.
- rustls is the sole TLS implementation at every configuration: not as a
  default, not behind a feature flag and not as a fallback. Certificate
  validation is on by default, and `--insecure` emits a warning on stderr
  before proceeding. The emitter behind that last requirement is delivered:
  `curl-rs/src/output/msgs.rs` routes the warning so that no verbosity gate can
  suppress it, and asserts as much across every combination of the silent and
  show-error gates, for `--insecure`, `--proxy-insecure` and `--doh-insecure`
  alike. The option parsing that would reach it is not yet on disk, so the
  end-to-end behavior remains target state while the emitter is real.
- every fixture eligible under the honestly advertised feature and protocol
  set passes unmodified.

That last item is the pass criterion for the test suite, and the accounting
below is the reason it takes that shape. The harness reads the
`Protocols:` and `Features:` lines of `curl --version` and decides fixture
eligibility from them, so under-reporting a capability makes a fixture skip
while over-reporting makes it run and fail.

- The corpus comprises 1,914 fixtures.
- 1,476 of them contain a byte-exact `<protocol>` expectation, compared as
  full request strings, so header order matters.
- Approximately 1,413 fixtures, or 73.8% of the corpus, target the nine
  implemented schemes, distributed as HTTP 1029, FTP 257, SFTP 40, HTTPS 38,
  FILE 27, SCP 13 and FTPS 9.
- Approximately 283 fixtures, or 14.8% of the corpus, target protocols
  outside the implementation scope and skip legitimately, because those
  protocols are not advertised: SMTP 91, IMAP 73, POP3 54, MQTT 22, TFTP 18,
  RTSP 10, GOPHER 6, TELNET 4, SMB 2, DICT 2 and LDAP 1.
- Withholding the `Debug` token makes a further 98 fixtures skip, and
  disables torture mode.

The criterion, stated exactly: every fixture eligible under the honestly
advertised feature and protocol set passes unmodified. That result must never
be summarized as a claim that the whole suite passes, nor as a percentage of
the suite passing.

Torture testing is not applicable to the specified default `Rust` target,
because the memory-tracking capability the harness requires for torture mode
is derived from a `Debug` token that the specified default target does not
advertise; see [`TEST-SUITE`](TEST-SUITE.md) for that mechanism.

If the pull-request fails one of these tests, it shows up as a red X and you
are expected to fix the problem. If you do not understand what the issue is or
have other problems to fix the complaint, just ask and other project members
can likely help out.

Consider the following table while looking at pull request failures:

| CI platform as shown in PR          | State  | What to look at next       |
| ----------------------------------- | ------ | -------------------------- |
| Linux / macOS / Windows / ...       | stable | all errors and failures    |
| Fuzzer                              | stable | fuzzing results            |
| Code analyzers                      | stable | new findings               |
| Docs / URLs / Hygiene / ...         | stable | all errors and failures    |
| AppVeyor                            | stable | all errors and failures    |
| buildbot/curl_Schannel ...          | stable | all errors and failures    |
| curl.curl (linux ...)               | stable | all errors and failures    |

The `Rust` checks - `Rust build`, `Rust lint`, `Rust tests`,
`Rust undefined behaviour`, `Rust sanitizer`, `Rust coverage`,
`Rust supply chain`, `Rust ABI parity` and `curl test suite` - are all
committed. Several of them are red today because they guard parts of the
target design that have not been built yet, so a red X on one of those reports
that condition rather than a defect in the check. The
[Specified Rust workflows](#specified-rust-workflows) section below gives the
inventory and says which is which. The `checksrc` and Autotools distribution
checks that this table listed previously no longer exist as workflows; see the
end of that same section.

Sometimes the tests fail or run slowly due to a dependency service temporarily
having issues, for example package downloads, or virtualized (non-native)
environments. Sometimes a flaky failed test may occur in any jobs.

Windows jobs have a number of flaky issues, most often, these:
- test run hanging and timing out after 20 minutes.
- test run aborting with 2304 (hex 0900) or 3840 (hex 0F00).
- test run crashing with fork errors.
- steps past the test run exiting with -1073741502 (hex C0000142).

In these cases you can just try to update your pull requests to rerun the tests
later as described below.

A detailed overview of test runs and results can be found on
[Test Clutch](https://testclutch.curl.se/).

## CI servers

Here are the different CI environments that are currently in use, and how they
are configured:

### GitHub Actions (GHA)

GitHub Actions runs the following tests:

- Tests with a variety of different compilation options, OSes, CPUs.
- Fuzz tests ([see the curl-fuzzer repo for more
  info](https://github.com/curl/curl-fuzzer)).
- Static analysis and sanitizers: clang-tidy, scan-build, address sanitizer,
  memory sanitizer, thread sanitizer, CodeQL, valgrind, torture tests.

These are each configured in different files in `.github/workflows`.

### AppVeyor CI

AppVeyor runs a variety of different Windows builds, with different compilation
options.

As of October 2025 `@bagder`, `@mback2k`, `@jay`, `@vszakats`, `@dfandrich`
and `@danielgustafsson` have administrator access to the AppVeyor CI
environment. Additional admins/group members can be added on request.

The tests are configured in `appveyor.yml`.

### Circle CI

Circle CI runs a basic Linux test suite on Ubuntu for both x86 and ARM
processors. This is configured in `.circleci/config.yml`.

You can [view the full list of CI jobs on Circle CI's
website](https://app.circleci.com/pipelines/github/curl/curl).

`@bagder` has access to edit the "Project Settings" on that page. Additional
admins/group members can be added on request.

## Specified Rust workflows

All nine gates below are present in `.github/workflows/` and run on push and
pull request. One gate lives in one file, so that a failure names its own
cause.

Several of them are RED today, and deliberately so. Each guards a part of the
target design that has not been built yet, and each fails with a message that
names the missing subject rather than passing over an empty set. A gate that
went green because the thing it measures does not exist would be worse than no
gate at all: it would report success for work that was never done. Where a gate
is currently red, the entry below says so and says why.

One committed file is deliberately absent from the nine. `hygiene.yml` is not
one of the specified `Rust` gates, but two of its jobs reach the `Rust` target
and it is worth naming for that reason: its `badwords` step reads
`curl-rs-lib/src`, `curl-rs/src` and `curl-rs-ffi/src` by name, and `codespell`
runs over every tracked file, so the prose in the `Rust` sources is gated even
though it is not behavior; and its `checksrc` job grades the public C headers,
eight of which `curl-rs-ffi` generates. Both are described again at the end of
this section.

- `rust-build.yml` (gate 1) builds the whole `workspace` in release mode,
  warning-free, across the four-target matrix, and separately checks that the
  crates still compile on the pinned minimum supported `Rust` version.
- `rust-clippy.yml` (gate 2) runs `cargo clippy` across the `workspace` with
  warnings promoted to errors.
- `rust-test.yml` (gate 3) runs the full `cargo test` across the `workspace`,
  both with default features and with all features. It enumerates the test
  executables `cargo` plans to build and then requires every one of them to
  appear in the run, so a suite that silently stopped being compiled cannot go
  unnoticed. The `unsafe_boundary` and `source_policy` checks that enforce the
  crate-level `unsafe` policy live in `#[cfg(test)]` modules, which makes them
  this gate's responsibility rather than the build's.
- `curl-testsuite.yml` (gate 4) drives the retained Perl harness against the
  `Rust` binary through the harness's own `-c` binary-selection option, judged
  by the eligible-fixture criterion above. Not one file under `tests/` is
  modified, and the gate asserts that before and after the run. **Red today:**
  the binary cannot yet answer `--version`, and the harness reads that output to
  decide which fixtures are eligible, so the gate stops there with an
  explanation instead of reporting a wall of consequential failures.
- `rust-miri.yml` (gate 5) runs `Miri` over `curl-rs-lib`, requiring no
  undefined behavior, on a dated nightly pinned in the workflow so that an
  unchanged commit cannot gain or lose findings as the aliasing model evolves.
- `rust-asan.yml` (gate 6) runs the tests under `AddressSanitizer` across the
  `FFI` surface, requiring no errors. It re-reads the compiled test binaries and
  requires each to carry the sanitizer runtime, so the gate cannot quietly
  decay into a second copy of gate 3 if the instrumentation flags stop taking
  effect.
- `rust-abi.yml` (gate 7) checks exported-symbol parity against
  `lib/libcurl.def`, the sole export authority, which lists exactly 100 names.
  The comparison is symmetric: a missing symbol breaks an existing consumer, and
  an extra one enlarges the public surface beyond curl 8.19.0-DEV. The same gate
  compiles all 129 standalone programs under `docs/examples/` against the
  generated public header; they are compiled and never edited. That compilation
  is a differential -- every program is built twice, once against the committed
  headers and once against the generated ones, and only a program that the
  committed headers compile and the generated headers do not counts as a
  failure. Seven of the 129 do not compile against the committed headers either,
  for reasons belonging to the corpus rather than to this workspace, and the
  differential subtracts them without a hand-maintained skip list.
  **Red today, for two independent reasons:** none of the 100 symbols is
  exported yet, and the generated header is missing whole families of type
  declarations, so it breaks C programs that the committed header builds.
- `rust-coverage.yml` (gate 8) runs `cargo llvm-cov` and requires at least 80%
  line coverage on `curl-rs-lib/src/protocols/` and `curl-rs-lib/src/transfer/`.
  That figure is the minimum the gate demands of those two module trees, never a
  result claimed for the code. The per-tree arithmetic is computed explicitly
  rather than delegated to a whole-workspace threshold, because a workspace total
  can sit comfortably above 80% while either mandated tree contributes nothing at
  all. **Red today:** neither module tree exists yet, and the gate says so rather
  than scoring an empty set.
- `rust-audit.yml` (gate 9) scans dependency advisories and requires no critical
  findings, alongside a policy check over dependency licensing and duplicate
  versions. Its accepted-advisory list is symmetric and self-expiring: an
  advisory that is reported but not accepted fails, and so does one that is
  accepted but no longer reported.

Gate 10 of the ten, that certificate validation is on by default, is asserted by
integration tests rather than by a workflow of its own, and therefore runs as
part of gate 3.

Four of the checks that guarded the retained C build lost their purpose once the
build system was replaced, and they have been removed rather than edited: the
comparison of the two build systems had nothing left to compare, the Autotools
distribution check had no Autotools distribution, the C style check is superseded
by `clippy` and `rustfmt` over `Rust` code, and the Windows cross-build targeted a
platform outside the four-target matrix.

The C style check is the one of those four that is superseded only in part,
and the split matters. `scripts/checksrc-all.pl` graded two populations: the C
implementation sources under `lib/` and `src/`, which the `Rust` tree
supersedes, and the twelve public C headers under `include/curl/`, which it
does not, because those headers remain the C ABI contract and eight of them
are generated by `curl-rs-ffi`. `clippy` and `rustfmt` replace the first half
only. The second half is graded by a `checksrc` job in `hygiene.yml`, which
runs `scripts/checksrc.pl` over `include/curl` alone, so `scripts/checksrc.pl`
stays on disk. That job is independent of exported-symbol parity: compiling a
header proves it is usable, and says nothing about whether it is well-formed.

The jobs described earlier on this page verify the retained C build: the
static analysis and sanitizer jobs, the documentation and style checks,
AppVeyor, the Schannel buildbot and Circle CI. None of them compiles the
specified `Rust` target. Two of them touch it without compiling it: the header
`checksrc` job just described grades the twelve public C headers, eight of
which `curl-rs-ffi` generates, and `hygiene.yml` runs its prose checks over
`curl-rs-lib/src`, `curl-rs/src` and `curl-rs-ffi/src` as well as over the C
sources.
