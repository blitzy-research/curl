<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# The curl HTTP Test Suite

This is an additional test suite using a combination of Apache httpd and
nghttpx servers to perform various tests beyond the capabilities of the
standard curl test suite.

This suite drives the curl command-line binary externally rather than linking
against the library, so it exercises whatever binary it is pointed at. That
property is what lets the specified `Rust` command-line binary, `curl-rs`,
substitute for the C binary with no change to this suite, to `conftest.py`, to
the `testenv` package, to the server configuration or to any test case. The
suite and its servers are retained unchanged. The substitution itself is not
available yet: the `curl-rs` binary has no entry point on disk, so nothing here
has been run against it.

# Usage

The test cases and necessary files are in `tests/http`. You can invoke
`pytest` from there or from the top level curl checkout and it finds all
tests.

```
curl> pytest test/http
platform darwin -- Python 3.9.15, pytest-6.2.0, py-1.10.0, pluggy-0.13.1
rootdir: /Users/sei/projects/curl
collected 5 items

tests/http/test_01_basic.py .....
```

Pytest takes arguments. `-v` increases its verbosity and can be used several
times. `-k <expr>` can be used to run only matching test cases. The `expr` can
be something resembling a python test or just a string that needs to match
test cases in their names.

```
curl/tests/http> pytest -vv -k test_01_02
```

runs all test cases that have `test_01_02` in their name. This does not have
to be the start of the name.

Depending on your setup, some test cases may be skipped and appear as `s` in
the output. If you run pytest verbose, it also gives you the reason for
skipping.

# Prerequisites

You need:

1. a recent Python, the `cryptography` module and, of course, `pytest`
2. an apache httpd development version. On Debian/Ubuntu, the package
   `apache2-dev` has this
3. a local `curl` project build
3. optionally, a `nghttpx` with HTTP/3 enabled or h3 test cases are skipped

### Configuration

Via curl's `configure` script you may specify:

  * `--with-test-nghttpx=<path-of-nghttpx>` if you have nghttpx to use
   somewhere outside your `$PATH`.

  * `--with-test-httpd=<httpd-install-path>` if you have an Apache httpd
   installed somewhere else. On Debian/Ubuntu it otherwise looks into
   `/usr/bin` and `/usr/sbin` to find those.

  * `--with-test-caddy=<caddy-install-path>` if you have a Caddy web server
   installed somewhere else.

  * `--with-test-vsftpd=<vsftpd-install-path>` if you have a vsftpd ftp
   server installed somewhere else.

  * `--with-test-danted=<danted-path>` if you have `dante-server` installed

## Usage Tips

Several test cases are parameterized, for example with the HTTP version to
use. If you want to run a test with a particular protocol only, use a command
line like:

```
curl/tests/http> pytest -k "test_02_06 and h2"
```

Test cases can be repeated, with the `pytest-repeat` module (`pip install
pytest-repeat`). Like in:

```
curl/tests/http> pytest -k "test_02_06 and h2" --count=100
```

which then runs this test case a hundred times. In case of flaky tests, you
can make pytest stop on the first one with:

```
curl/tests/http> pytest -k "test_02_06 and h2" --count=100 --maxfail=1
```

which allow you to inspect output and log files for the failed run. Speaking
of log files, the verbosity of pytest is also used to collect curl trace
output. If you specify `-v` three times, the `curl` command is started with
`--trace`:

```
curl/tests/http> pytest -vvv -k "test_02_06 and h2" --count=100 --maxfail=1
```

all of curl's output and trace file are found in `tests/http/gen/curl`.

## Writing Tests

There is a lot of [`pytest` documentation](https://docs.pytest.org/) with
examples. No use in repeating that here. Assuming you are somewhat familiar
with it, it is useful how *this* general test suite is setup. Especially if
you want to add test cases.

### Servers

In `conftest.py` 3 "fixtures" are defined that are used by all test cases:

1. `env`: the test environment. It is an instance of class
   `testenv/env.py:Env`. It holds all information about paths, availability of
   features (HTTP/3), port numbers to use, domains and SSL certificates for
   those.
2. `httpd`: the Apache httpd instance, configured and started, then stopped at
   the end of the test suite. It has sites configured for the domains from
   `env`. It also loads a local module `mod_curltest?` and makes it available
   in certain locations. (more on mod_curltest below).
3. `nghttpx`: an instance of nghttpx that provides HTTP/3 support. `nghttpx`
   proxies those requests to the `httpd` server. In a direct mapping, so you
   may access all the resources under the same path as with HTTP/2. Only the
   port number used for HTTP/3 requests are different.

`pytest` manages these fixture so that they are created once and terminated
before exit. This means you can `Ctrl-C` a running pytest and the server then
shutdowns. Only when you brutally chop its head off, might there be servers
left behind.

### Test Cases

Tests making use of these fixtures have them in their parameter list. This
tells pytest that a particular test needs them, so it has to create them.
Since one can invoke pytest for just a single test, it is important that a
test references the ones it needs.

All test cases start with `test_` in their name. We use a double number scheme
to group them. This makes it ease to run only specific tests and also give a
short mnemonic to communicate trouble with others in the project. Otherwise
you are free to name test cases as you think fitting.

Tests are grouped thematically in a file with a single Python test class. This
is convenient if you need a special "fixture" for several tests. "fixtures"
can have "class" scope.

There is a curl helper class that knows how to invoke curl and interpret its
output. Among other things, it does add the local CA to the command line, so
that SSL connections to the test servers are verified. Nothing prevents anyone
from running curl directly, for specific uses not covered by the `CurlClient`
class.

### mod_curltest

The module source code is found in `testenv/mod_curltest`. It is compiled
using the `apxs` command, commonly provided via the `apache2-dev` package.
Compilation is quick and done once at the start of a test run.

The module adds 2 "handlers" to the Apache server (right now). Handler are
pieces of code that receive HTTP requests and generate the response. Those
handlers are:

* `curltest-echo`: hooked up on the path `/curltest/echo`. This one echoes
  a request and copies all data from the request body to the response body.
  Useful for simulating upload and checking that the data arrived as intended.

* `curltest-tweak`: hooked up on the path `/curltest/tweak`. This handler is
  more of a Swiss army knife. It interprets parameters from the URL query
  string to drive its behavior.

  * `status=nnn`: generate a response with HTTP status code `nnn`.
  * `chunks=n`: generate `n` chunks of data in the response body, defaults to 3.
  * `chunk_size=nnn`: each chunk should contain `nnn` bytes of data. Maximum is 16KB right now.
  * `chunkd_delay=duration`: wait `duration` time between writing chunks
  * `delay=duration`: wait `duration` time to send the response headers
  * `body_error=(timeout|reset)`: produce an error after the first chunk in the response body
  * `id=str`: add `str` in the response header `request-id`

`duration` values are integers, optionally followed by a unit. Units are:

  * `d`: days (probably not useful here)
  * `h`: hours
  * `mi`: minutes
  * `s`: seconds (the default)
  * `ms`: milliseconds

As you can see, `mod_curltest`'s tweak handler allows Apache to simulate many
kinds of responses. An example of its use is `test_03_01` where responses are
delayed using `chunk_delay`. This gives the response a defined duration and the
test uses that to reload `httpd` in the middle of the first request. A graceful
reload in httpd lets ongoing requests finish, but closes the connection
afterwards and tears down the serving process. The following request then needs
to open a new connection. This is verified by the test case.

## Notes on the specified Rust target

### Byte-exact request comparison

The standard curl test suite compares the request bytes a client sends against
a literal expectation. In `tests/getpart.pm`, `sub compareparts` at lines
351-357 joins each side into a single string and compares the two strings, so
header order, header casing and header spacing are all significant. The only
escape is the `%alternatives[a,b]` construct together with the `<strip>` and
`<strippart>` rules, which are applied before the comparison. The `<protocol>`
tag that carries these expectations is documented in
[`FILEFORMAT`](FILEFORMAT.md).

The HTTP/1.1 request writer specified for `curl-rs-lib` is therefore required
to own request-line composition and header serialization itself, and to emit
headers in curl's exact order. The `hyper` `crate` is specified for connection
management, keep-alive and framing. Header emission policy and ordering remain
curl's own, and are specified to be reproduced by the `Rust` implementation
rather than delegated. No such writer is on disk yet, so none of this has been
measured against the corpus.

### HTTP/2 and HTTP/3 boundaries

HTTP/2 is specified over the `h2` `crate`, with ALPN negotiated by rustls. The
`h2` `crate` is declared alongside `hyper` because direct control of `SETTINGS`
frames and flow-control windows is observable in the standard suite's
expectations and is not reachable through the higher-level surface.

HTTP/3 is specified over the `quinn` and `h3` `crates`, using the
`AsyncUdpSocket` abstraction, and joins the same connection-filter chain that
carries TLS and raw sockets. In the retained C tree HTTP/3 is already a
connection filter: `lib/vquic/vquic.h` line 48 declares
`extern struct Curl_cftype Curl_cft_http3;`. The specification preserves that
arrangement rather than replacing it.

The nghttpx server in this suite continues to provide the HTTP/3 endpoint. The
`nghttpx` and `h3` availability tokens the harness recognizes describe the test
servers, not the capabilities of the binary under test.

### Certificate verification in this suite

The `CurlClient` helper already adds the local CA to the command line so the
connections to the test servers are verified, as documented above, and that
arrangement is unaffected. For the specified target, rustls is the sole TLS
implementation at every configuration and certificate validation is on by
default. The warning that `--insecure` prints on stderr before the transfer
proceeds is delivered in `curl-rs`, and no verbosity option suppresses it,
`--silent` included; what is still absent is the option parsing that would
reach it and the TLS backend whose verification it reports on.

### What does not change

The httpd and nghttpx server configuration, the `conftest.py` fixtures, the
`testenv` package, the `--with-test-*` switches, the `mod_curltest` handlers,
plus every test case in `tests/http`, are retained unchanged. A case that
fails is evidence of a defect in the implementation under test, never a reason
to edit the case or the server configuration.
