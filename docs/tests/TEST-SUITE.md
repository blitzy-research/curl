<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# The curl Test Suite

# Running

See the "Requires to run" section for prerequisites.

In the root of the curl repository:

    ./configure && make && make test

To run a specific set of tests (e.g. 303 and 410):

    make test TFLAGS="303 410"

To run the tests faster, pass the -j (parallelism) flag:

    make test TFLAGS="-j10"

"make test" builds the test suite support code and invokes the 'runtests.pl'
perl script to run all the tests. The value of `TFLAGS` is passed directly
to 'runtests.pl'.

When you run tests via make, the flags `-a` and `-s` are passed, meaning to
continue running tests even after one fails, and to emit short output.

If you would like to not use those flags, you can run 'runtests.pl'
directly. You must `chdir` into the tests directory, then you can run it
like so:

    ./runtests.pl 303 410

You must have run `make test` at least once first to build the support code.

To see what flags are available for runtests.pl, and what output it emits,
run:

    man ./docs/runtests.1

After a test fails, examine the tests/log directory for stdout, stderr, and
output from the servers used in the test.

## Testing the specified Rust binary

The harness selects the binary under test through the `runtests.pl` `-c`
option. Its own help output describes that option as
`-c path  use this curl executable`. The specified `curl-rs` command-line
binary substitutes for the C binary through this documented option, so no
change to the harness is required in order to exercise it.

Two companion options matter while bootstrapping a run. `-vc <path>` selects
the curl used only to verify that the test servers are up, and `-ac <path>`
selects the curl used only to talk to continuous-integration test APIs.
Pointing either of those at a system curl avoids a circular dependency while
the binary under test is the one being exercised. No Perl module, no mock
server and no test case is modified in order to run the suite against a
different binary.

During start-up the harness runs `curl --version` and parses two lines of
the output. The `Protocols:` line is handed to `parseprotocols`, which
derives a `-ipv6` and a `-unix` variant of every name it finds and then
appends `http-proxy` and `https-mtls`. The `Features:` line populates a
feature map over a fixed vocabulary of names, spelled exactly as the harness
spells them.

The binary therefore describes itself to the harness, and the harness
believes it. 874 of the test cases gate on a `<features>` requirement, which
makes one asymmetry decisive. **Under-reporting a capability makes a fixture
skip; over-reporting makes it run and fail.** Truthful advertisement is
therefore the optimal strategy as well as the honest one.

The specified target advertises only the protocols it implements. Those nine
schemes are `file`, `ftp`, `ftps`, `http`, `https`, `scp`, `sftp`, `ws` and
`wss`. Every other registered scheme keeps its public protocol constant for
ABI completeness and returns an unsupported-protocol error, and each is
withheld from the `Protocols:` line so that the cases requiring it skip
rather than fail.

The harness sets its own `rustls` feature from a `rustls-ffi` token in the
libcurl version banner, at `tests/runtests.pl` lines 585-586, rather than
from the word rustls alone. That branch is also the one branch of the TLS
detection which leaves the `SSLpinning` feature unset. The specified target
uses rustls as a native library rather than through its C FFI layer, so a
truthful banner does not match that token and the cases gated on the harness
`rustls` feature skip. The resolution is deliberate: truthful product
identification is preferred over emitting a token that would describe the
implementation incorrectly, and the resulting skips are accepted. That
follows the same asymmetry, under which under-reporting is the safe
direction.

## What "the suite passes" means

The corpus under `tests/data` comprises 1,914 cases, and the honest way to
describe a run is to account for which of them are eligible.

- 1,476 cases contain a byte-exact `<protocol>` expectation. The comparison
  is a full-string comparison, so header order, casing and spacing all
  matter: `sub compareparts` in `tests/getpart.pm` joins each side into a
  single string before comparing. The `%alternatives[a,b]` construct and the
  `<strip>` and `<strippart>` rules are the only escapes. The tag itself is
  documented in [`FILEFORMAT`](FILEFORMAT.md).
- 874 cases gate on a `<features>` requirement and 28 carry a `<limits>`
  allocation cap.
- Approximately 1,413 cases, or 73.8% of the corpus, target the nine
  implemented schemes: HTTP 1029, FTP 257, SFTP 40, HTTPS 38, FILE 27,
  SCP 13 and FTPS 9.
- Approximately 283 cases, or 14.8% of the corpus, target protocols outside
  the implementation scope and skip legitimately, because those protocols
  are not advertised: SMTP 91, IMAP 73, POP3 54, MQTT 22, TFTP 18, RTSP 10,
  GOPHER 6, TELNET 4, SMB 2, DICT 2 and LDAP 1.
- Withholding the `Debug` token makes a further 98 cases skip, and disables
  torture mode.

The success criterion is therefore precise: every fixture eligible under the
honestly advertised feature and protocol set passes unmodified. That result
must never be summarized as a claim that the whole suite passes, nor as a
percentage of the suite passing; both statements are inaccurate and are
prohibited throughout this documentation.

## Requires to run

- `perl` (and a Unix-style shell)
- `python` (and a Unix-style shell, for SMB and TELNET tests)
- `python-impacket` (for SMB tests)
- `diff` (when a test fails, a diff is shown)
- `stunnel` (for HTTPS and FTPS tests)
- `openssl` (the command line tool, for generating test server certificates)
- `openssh` or `SunSSH` (for SCP and SFTP tests)
- `nghttpx` (for HTTP/2 and HTTP/3 tests)

### Installation of impacket

The Python-based test servers support Python 3.

Please install python-impacket in the correct Python environment. You can
use pip or your OS' package manager to install 'impacket'.

On Debian/Ubuntu the package name is 'python3-impacket'

On FreeBSD the package name is 'py311-impacket'

On any system where pip is available: 'python3 -m pip install impacket'

You may also need to manually install the Python package 'six' as that may
be a missing requirement for impacket.

## Event-based

When the binary under test advertises a `Debug` token in its `Features:`
line (see below), the `runtests.pl` script offers a `-e` option (or
`--test-event`) that makes it perform *event-based*. The harness gates this
on what the binary advertises, not on how it was built. Such tests invokes
the curl tool with `--test-event`, a debug-only option made for this purpose.

Performing event-based means that the curl tool uses the
`curl_multi_socket_action()` API call to drive the transfer(s), instead of
the otherwise "normal" functions it would use. This allows us to test drive
the socket_action API. Transfers done this way should work exactly the same
as with the non-event based API.

To be able to use `--test-event` together with `--parallel`, curl requires
*libuv* to be present and enabled in the build: `configure --enable-libuv`

The specified default `Rust` target advertises no `Debug` token, so the
harness does not exercise this mode against it by default. Both
`configure --enable-libuv` and the debug-only `--test-event` option are
mechanisms of the retained C build.

## Duplicated handles

When the binary under test advertises a `Debug` token in its `Features:`
line (see below), the `runtests.pl` script offers a `--test-duphandle`
option. Here too the gate is what the binary advertises rather than how it
was built. When enabled, curl always duplicates the easy handle and does its
transfers using the new one instead of the original. This is done entirely
for testing purpose to verify that everything works exactly the same when
this is done; confirming that the `curl_easy_duphandle()` function duplicates
everything that it should.

The specified default `Rust` target advertises no `Debug` token, so the
harness does not exercise this mode against it by default either.

### Port numbers used by test servers

All test servers run on "random" port numbers. All tests must be written to
use the suitable variables instead of fixed port numbers so that test cases
continue to work independently of what port numbers the test servers
actually use.

See [`FILEFORMAT`](FILEFORMAT.md) for the port number variables.

### Test servers

The test suite runs stand-alone servers on random ports to which it makes
requests. For SSL tests, it runs stunnel to handle encryption to the regular
servers. For SSH, it runs a standard OpenSSH server.

The listen port numbers for the test servers are picked randomly to allow
users to run multiple test cases concurrently and to not collide with other
existing services that might listen to ports on the machine.

The HTTP server supports listening on a Unix domain socket, the default
location is 'http.sock'.

For HTTP/2 and HTTP/3 testing an installed `nghttpx` is used. HTTP/3 tests
check if nghttpx supports the protocol. To override the nghttpx used, set
the environment variable `NGHTTPX`. The default can also be changed by
specifying `--with-test-nghttpx=<path>` as argument to `configure`.

### DNS server

There is a test DNS server to allow tests to resolve hostnames to verify
those code paths. This server is started like all the other servers within
the `<servers>` section.

When such a test runs, the harness sets the environment variable
`CURL_DNS_SERVER` to identify the IP address and port number of the DNS
server to use. Honoring that variable is a property of the binary under test
rather than of a build flag.

In the retained C build, two paths lead there:

- curl built to use c-ares for resolving automatically asks that server for
  host information

- curl built to use `getaddrinfo()` for resolving *and* is built with c-ares
  1.26.0 or later, gets a special work-around. In such builds, when the
  environment variable is set, curl instead invokes a getaddrinfo wrapper
  that emulates the function and acknowledges the DNS server environment
  variable. This way, the getaddrinfo-using code paths in curl are verified,
  and yet the custom responses from the test DNS server are used.

curl that is built to support a custom DNS server in a test gets the
`override-dns` feature set.

In the retained C build, HTTPS resource-record lookups go through the c-ares
path, and in a debug build such lookups respect the DNS server environment
variable as well.

The specified target does not use c-ares at all: c-ares is dropped, and
`lib/asyn-ares.c` is not migrated. The specified target uses the system
resolver by default, with the `hickory-dns` `crate` specified as an optional
resolver behind a `Cargo` feature that is off by default. HTTPS
resource-record handling and DNS-over-HTTPS are specified as the target
modules `curl-rs-lib/src/dns/httpsrr.rs` and `curl-rs-lib/src/dns/doh.rs`,
neither of which is a current file. The retained C build implements resolver
timeouts with `alarm()` together with `sigsetjmp` and `siglongjmp`; the
specified target replaces that construct with `tokio::time::timeout`, and the
threaded-resolver abstraction is subsumed by the `async` runtime.

The test DNS server only has a few limited responses. When asked for

- type `A` response, it returns the address `127.0.0.1` three times
- type `AAAA` response, it returns the address `::1` three times
- other types, it returns a blank response without answers

### Shell startup scripts

Tests which use the ssh test server, SCP/SFTP tests, might be badly
influenced by the output of system wide or user specific shell startup
scripts, .bashrc, .profile, /etc/csh.cshrc, .login, /etc/bashrc, etc. which
output text messages or escape sequences on user login. When these shell
startup messages or escape sequences are output they might corrupt the
expected stream of data which flows to the sftp-server or from the ssh
client which can result in bad test behavior or even prevent the test server
from running.

If the test suite ssh or sftp server fails to start up and logs the message
'Received message too long' then you are certainly suffering the unwanted
output of a shell startup script. Locate, cleanup or adjust the shell
script.

### Memory test

The test script checks that all allocated memory is freed properly, but it
only does so when the binary under test advertises a `Debug` token in its
`Features:` line. From that line `tests/runtests.pl` sets
`$feature{"TrackMemory"} = $feat =~ /Debug/i;` and
`$feature{"Debug"} = $feat =~ /Debug/i;`, and the entire memory-checking
block is wrapped in `if($feature{"TrackMemory"})`. When the token is absent,
both the leak check and the allocation-cap check are skipped, and a missing
memory-dump file records only a marker rather than a failure.

The allocation figures in a `<limits>` block are caps rather than equality
checks. The harness defaults to 1000 allocations and one million bytes when
a case omits the block, and then compares with a greater-than test, so an
allocation count that differs without being larger passes. `tests/data/test1`
is the canonical example, specifying an allocation count and a maximum
allocated size.

Torture mode, reached through the `runtests.pl` `-t` option and through
`make torture-test`, hard-requires the advertised memory-tracking feature:
without it the harness stops with an error rather than degrading. Torture
mode runs each test many times and makes each different memory allocation
fail on each successive run. This tests the out of memory error handling code
to ensure that memory leaks do not occur even in those situations.

The specified default `Rust` target advertises no `Debug` token. The 28 cases
that carry a `<limits>` allocation cap are therefore inert, the 98 cases that
require `Debug` skip, and `make torture-test` is not applicable to the
specified target. A default-off `memdebug` `Cargo` feature is specified,
rather than present, as the mechanism that could restore this accounting by
reproducing the log format the harness already parses. That format is fully
specified by the retained C tree: records of the form
`MEM <source>:<line> malloc(<size>) = <pointer>`, with parallel forms for
`calloc`, `strdup`, `wcsdup`, `realloc` and `free`, plus `LIMIT`, `FD`,
`FILE` and `ADDR` records. `tests/memanalyzer.pm` parses them, and
`tests/runner.pm` sets the destination through the `CURL_MEMDEBUG`
environment variable. An individual case can opt out with
`<command option="no-memdebug">`.

The `DEBUGBUILD` define, the `memanalyze.pl` script that analyzes the memory
debugging output, and `CPPFLAGS=-DMEMDEBUG_LOG_SYNC`, which helps ensure that
the memory log file is written even if curl crashes, are all mechanisms of
the retained C build.

Also, if you run tests on a machine where valgrind is found, the script uses
valgrind to run the test with (unless you use `-n`) to further verify
correctness. Valgrind runs against whichever binary the harness is pointed
at.

### Debug

If a test case fails, you can conveniently get the script to invoke the
debugger (gdb) for you with the server running and the same command line
parameters that failed. Just invoke `runtests.pl <test number> -g` and then
just type 'run' in the debugger to perform the command through the debugger.

### Logs

All logs are generated in the log/ subdirectory (it is emptied first in the
runtests.pl script). They remain in there after a test run.

### Log Verbosity

In the retained C build, `--enable-debug` offers more verbose output in the
logs. This applies not only for test cases, but also when running it
standalone with `curl -v`. While a curl debug built is
***not suitable for production***, it is often helpful in tracking down
problems.

Sometimes, one needs detailed logging of operations, but does not want
to drown in output. The newly introduced *connection filters* allows one to
dynamically increase log verbosity for a particular *filter type*. Example:

    CURL_DEBUG=ssl curl -v https://curl.se/

makes the `ssl` connection filter log more details. One may do that for
every filter type and also use a combination of names, separated by `,` or
space.

    CURL_DEBUG=ssl,http/2 curl -v https://curl.se/

The order of filter type names is not relevant. Names used here are
case insensitive. Note that these names are implementation internals and
subject to change.

Some, likely stable names are `tcp`, `ssl`, `http/2`. For a current list,
one may search the retained C tree for `struct Curl_cftype` definitions and
find the names there. Also, some filters are only available with certain
build options, of course.

The specified target expresses the same connection filter chain as a `Rust`
trait carrying a typed context, in the specified module
`curl-rs-lib/src/conn/filters.rs`.

### Test input files

All test cases are put in the `data/` subdirectory. Each test is stored in
the file named according to the test number.

See [`FILEFORMAT`](FILEFORMAT.md) for a description of the test case file
format.

### Code coverage

The instrumentation described next belongs to the retained C build.

gcc provides a tool that can determine the code coverage figures for the
test suite. To use it, configure curl with `CFLAGS='-fprofile-arcs
-ftest-coverage -g -O0'`. Make sure you run the normal and torture tests to
get more full coverage, i.e. do:

    make test
    make test-torture

The graphical tool `ggcov` can be used to browse the source and create
coverage reports on \*nix hosts:

    ggcov -r lib src

The text mode tool `gcov` may also be used, but it does not handle object
files in more than one directory correctly.

Coverage for the specified `Rust` `workspace` is measured with
`cargo llvm-cov`. The acceptance gate is a minimum of 80% line coverage on
the two specified module trees `curl-rs-lib/src/protocols/` and
`curl-rs-lib/src/transfer/`. That figure is a threshold the specified target
has to meet, not a measured result. The memory test section above explains
why `make torture-test` is not applicable to the specified default target.

### Remote testing

The runtests.pl script provides some hooks to allow curl to be tested on a
machine where perl can not be run. The test framework in this case runs on
a workstation where perl is available, while curl itself is run on a remote
system using ssh or some other remote execution method. See the comments at
the beginning of runtests.pl for details.

## Test case numbering

Test cases used to be numbered by category ranges, but the ranges filled
up. Subsets of tests can now be selected by passing keywords to the
runtests.pl script via the make `TFLAGS` variable.

New tests are added by finding a free number in `tests/data/Makefile.am`.

## Write tests

Here's a quick description on writing test cases. We basically have three
kinds of tests: the ones that test the curl tool, the ones that build small
applications and test libcurl directly and the unit tests that test
individual (possibly internal) functions.

### test data

Each test has a master file that controls all the test data. What to read,
what the protocol exchange should look like, what exit code to expect and
what command line arguments to use etc.

These files are `tests/data/test[num]` where `[num]` is just a unique
identifier described above, and the XML-like file format of them is
described in the separate [`FILEFORMAT`](FILEFORMAT.md) document.

### curl tests

A test case that runs the curl tool and verifies that it gets the correct
data, it sends the correct data, it uses the correct protocol primitives
etc.

### libcurl tests

The libcurl tests are identical to the curl ones, except that they use a
specific and dedicated custom-built program to run instead of "curl". This
tool is built from source code placed in `tests/libtest` and if you want to
make a new libcurl test that is where you add your code. `tests/libtest`
holds 235 such test programs, built from its `lib*.c` sources.

### unit tests

Unit tests are placed in `tests/unit`. There is a tests/unit/README
describing the specific set of checks and macros that may be used when
writing tests that verify behaviors of specific individual functions.
`tests/unit` holds 59 test programs.

In the retained C build, the unit tests depend on curl being built with debug
enabled.

Both `tests/libtest` and `tests/unit` hold C programs that link against a
static libcurl and call internal `Curl_*` symbols. In the specified `Rust`
implementation those internal items are crate-private, and they are genuinely
absent from the static library's symbol table rather than merely hidden, so
these programs cannot link unmodified, and no quality of implementation
changes that. Their assertions are relocated into the specified `Rust`
`crates` as `#[cfg(test)]` modules, or behind a specified `testing` `Cargo`
feature, which preserves the coverage without preserving the linkage.
Exporting internal symbols solely to satisfy these programs is explicitly
rejected, because it would defeat the encapsulation that the safety
guarantees depend on.

This deviation is strictly separate from `tests/data`. That case corpus
drives only the command-line binary through documented flags, so those cases
do pass unmodified.

### test bundles

Individual tests are bundled into single executables, one for libtests, one
for unit tests and one for servers. The executables' first argument is
the name of libtest, unit test or server respectively.
In these executables, the build process automatically renames the entry point
to a unique symbol. `test` becomes `test_<tool>`, e.g. `test_lib1598` or
`test_unit1305`. For servers `main` becomes `main_sws` for the `sws` server,
and so on. Other common symbols may also be suffixed the same way.

## Acceptance gates for the specified Rust target

The test infrastructure itself is retained. The C mock protocol servers under
`tests/server/` remain C and remain in use, `tests/certs/` remains the
certificate and key corpus, and the Perl harness modules are retained
unmodified.

The specified target uses rustls as its sole TLS implementation, at every
configuration. Certificate validation is on by default, a self-signed
certificate has to be rejected by default, and `--insecure` has to emit a
warning on stderr before proceeding. Both of those behaviors are covered by
dedicated integration tests specified under `tests-rs/integration/`, a
specified location that is not part of this checkout.

The items below are acceptance criteria that the specified target has to
satisfy. They are criteria, never results, and `docs/CODE_REVIEW.md` owns
their full treatment.

- A zero-warning release build of the whole `workspace` on four targets:
  `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-apple-darwin` and `aarch64-apple-darwin`.
- `cargo clippy` across the `workspace` with warnings promoted to errors.
- The full `cargo test` run across the `workspace`.
- Every eligible case of the retained corpus passing unmodified, per the
  accounting given earlier on this page.
- `Miri` over `curl-rs-lib` with no undefined behavior.
- `ASan` with no errors across the FFI surface.
- Exported-symbol parity against the retained authority `lib/libcurl.def`,
  which lists exactly 100 names.
- A minimum of 80% line coverage on `curl-rs-lib/src/protocols/` and
  `curl-rs-lib/src/transfer/`.
- A dependency-advisory scan with no critical findings.
- All 129 standalone programs under `docs/examples/` compiling unchanged
  against the generated public header, as an additional ABI gate. Those
  programs are compiled and never edited.

Three documentation gates have scopes that are easy to confuse.
`.github/scripts/verify-synopsis.pl` checks the synopses in
`docs/libcurl/curl*.md` against the public headers.
`.github/scripts/verify-examples.pl` compiles the examples embedded in
`docs/libcurl/curl*.md` and in `docs/libcurl/opts/*.md`. The 129 standalone
`docs/examples/*.c` files are compiled separately by the build system and
remain untouched.
