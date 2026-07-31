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

The release-tarball item there is specific to Autotools packaging. In the
specified target design that distribution check is replaced rather than
carried forward, because a `Cargo` `workspace` has no Autotools distribution
tarball to package.

The specified `Rust` target is verified for the following. Every item here
describes target state, and none of the gates behind it is present in this
checkout:

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
  before proceeding.
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
| checkdocs / checksrc / dist / ...   | stable | all errors and failures    |
| AppVeyor                            | stable | all errors and failures    |
| buildbot/curl_Schannel ...          | stable | all errors and failures    |
| curl.curl (linux ...)               | stable | all errors and failures    |

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
environment.  Additional admins/group members can be added on request.

The tests are configured in `appveyor.yml`.

### Circle CI

Circle CI runs a basic Linux test suite on Ubuntu for both x86 and ARM
processors. This is configured in `.circleci/config.yml`.

You can [view the full list of CI jobs on Circle CI's
website](https://app.circleci.com/pipelines/github/curl/curl).

`@bagder` has access to edit the "Project Settings" on that page. Additional
admins/group members can be added on request.

## Specified Rust workflows

The gates below are specified for the target design. None of these workflow
files is present in this checkout, so nothing here describes a job that runs
today. The design places one gate in one file, so that a failure names its
own cause:

- `rust-build.yml` is specified for the release build of the whole
  `workspace`, warning-free, across the four-target matrix.
- `rust-clippy.yml` is specified for `cargo clippy` across the `workspace`
  with warnings promoted to errors.
- `rust-test.yml` is specified for the full `cargo test` run across the
  `workspace`.
- `rust-miri.yml` is specified for `Miri` over `curl-rs-lib`, requiring no
  undefined behavior.
- `rust-asan.yml` is specified for `ASan` across the `FFI` surface, requiring
  no errors.
- `rust-coverage.yml` is specified for `cargo llvm-cov`, requiring at least
  80% line coverage on `curl-rs-lib/src/protocols/` and
  `curl-rs-lib/src/transfer/`. That figure is the minimum the gate demands
  of those two module trees, never a result claimed for the code.
- `rust-audit.yml` is specified for a dependency advisory scan that requires
  no critical findings, together with a policy check over dependency
  licensing and duplicate versions.
- `rust-abi.yml` is specified for exported-symbol parity against
  `lib/libcurl.def`, the sole export authority, which lists exactly 100
  names. The same gate compiles all 129 standalone programs under
  `docs/examples/` against the generated public header. Those programs are
  compiled and never edited.
- `curl-testsuite.yml` is specified for the retained Perl harness driven
  against the specified `Rust` binary through its documented
  binary-selection option, judged by the eligible-fixture criterion above.

Four of the checks that guard the retained C build lose their purpose once
the build system is replaced, and the target design replaces rather than
edits them: the comparison of the two build systems has nothing left to
compare, the Autotools distribution check has no Autotools distribution, the
C style check is superseded by `clippy` and `rustfmt` over `Rust` code, and
the Windows cross-build targets a platform outside the four-target matrix.
Each of those is a property of the specified target design.

The jobs described earlier on this page verify the retained C build: the
static analysis and sanitizer jobs, the documentation and style checks, the
distribution check, AppVeyor, the Schannel buildbot and Circle CI. None of
them validates the specified `Rust` target.
