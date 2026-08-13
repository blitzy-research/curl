<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# ENVIRONMENT
The environment variables can be specified in lower case or upper case. The
lower case version has precedence. `http_proxy` is an exception as it is only
available in lower case.

Using an environment variable to set the proxy has the same effect as using
the --proxy option.

## `http_proxy [protocol://]<host>[:port]`
Sets the proxy server to use for HTTP.

## `HTTPS_PROXY [protocol://]<host>[:port]`
Sets the proxy server to use for HTTPS.

## `[url-protocol]_PROXY [protocol://]<host>[:port]`
Sets the proxy server to use for [url-protocol], where the protocol is a
protocol that curl supports and as specified in a URL. FTP, FTPS, POP3, IMAP,
SMTP, LDAP, etc.

## `ALL_PROXY [protocol://]<host>[:port]`
Sets the proxy server to use if no protocol-specific proxy is set.

## `NO_PROXY <comma-separated list of hosts/domains>`
list of hostnames that should not go through any proxy. If set to an asterisk
'*' only, it matches all hosts. Each name in this list is matched as either a
domain name which contains the hostname, or the hostname itself.

This environment variable disables use of the proxy even when specified with
the --proxy option. That is

    NO_PROXY=direct.example.com curl -x http://proxy.example.com
    https://direct.example.com

accesses the target URL directly, and

    NO_PROXY=direct.example.com curl -x http://proxy.example.com
    https://somewhere.example.com

accesses the target URL through the proxy.

The list of hostnames can also include numerical IP addresses, and IPv6
versions should then be given without enclosing brackets.

IP addresses can be specified using CIDR notation: an appended slash and
number specifies the number of "network bits" out of the address to use in the
comparison (added in 7.86.0). For example "192.168.0.0/16" would match all
addresses starting with "192.168".

## `APPDATA <directory>`
On Windows, this variable is used when trying to find the home directory. If
the primary home variables are all unset.

## `COLUMNS <terminal width>`
If set, the specified number of characters is used as the terminal width when
the alternative progress-bar is shown. If not set, curl tries to figure it out
using other ways.

## `CURL_CA_BUNDLE <file>`
If set, it is used as the --cacert value, naming the CA bundle file that
server certificates are verified against.

Without it, the trust anchors are specified to be the ones bundled through the
`webpki-roots` crate, while --ca-native reads the platform trust store through
`rustls-native-certs` instead. Those two crates are both declared and are not
alternatives to one another, so choosing between them is a runtime decision
driven by curl's own options, --cacert, --capath, --ca-native and --insecure,
and never a build-time one. There is no unconditional fallback from one to the
other, and no `platform-verifier` mechanism is enabled that would take the
decision away from those options.

None of that is observable yet, and the reason is wiring rather than absence.
The TLS backend, its certificate-verification module, the trust-anchor handling
and the session cache are all on disk under `curl-rs-lib/src/tls/` and tested
there. What is missing is everything that would carry this variable to them: the
executable honours no command-line option, so the --cacert value this variable
supplies has nothing to reach, and no connection filter opens a TLS session. The
capability stays withheld from the advertised feature set until that path
exists, which is why this section states specified behavior rather than
behaviour a reader can exercise today. The same wiring gap applies to every TLS
variable below, and it is not repeated for each one.

## `CURL_HOME <directory>`
If set, is the first variable curl checks when trying to find its home
directory. If not set, it continues to check *XDG_CONFIG_HOME*

## `CURL_SSL_BACKEND <TLS backend>`
On a build that carries more than one TLS backend, this environment variable
names the backend to use for an invocation. A build that carries a single
backend has no alternative to select, and curl then keeps using that one
whatever the variable holds.

Exactly one TLS implementation is specified for this rewrite, `rustls`, so
this variable selects nothing and no C TLS library is linked. That much holds
today: no manifest in the workspace admits a second backend at any feature
setting, and the capability table withholds the `MultiSSL` name unconditionally
with tests asserting the withholding. What is not yet on disk is the printer for
the --version output that would show it, along with the parenthesized list of
further backends that a multiple-backend build prints -- so no banner is emitted
at all, and this variable has no selection to report either way.

## `HOME <directory>`
If set, this is used to find the home directory when that is needed. Like when
looking for the default .curlrc. *CURL_HOME* and *XDG_CONFIG_HOME*
have preference.

## `NETRC <path>`
If set, this is used to find the `.netrc` file. It overrides all other netrc
file location mechanisms and should be set to the full file path.
(Added in curl 8.16.0)

## `QLOGDIR <directory>`
If curl was built with HTTP/3 support, setting this environment variable to a
local directory makes curl produce **qlogs** in that directory, using file
names named after the destination connection id (in hex). Do note that these
files can become rather large. The QUIC transport specified for this rewrite
is `quinn` with `h3`, layered on the `AsyncUdpSocket` abstraction. That
transport is not on disk yet, so no such file is produced today.

## `SHELL`
Used on VMS when trying to detect if using a **DCL** or a **Unix** shell.

## `SSL_CERT_DIR <directory>`
If set, it is used as the --capath value, naming a directory that holds CA
certificates. A CA directory is not among the capabilities the specified TLS
backend offers: it leaves `SSLSUPP_CA_PATH` out, which makes `CURLOPT_CAPATH`
and --capath fail with `CURLE_NOT_BUILT_IN`. Point curl at a single CA bundle
file with --cacert, `CURL_CA_BUNDLE` or `SSL_CERT_FILE` instead. That capability
set is a permanent property of the backend rather than a stage of it, and the
backend declaring it is on disk; the refusal is specified behavior that no
command line can reach yet.

## `SSL_CERT_FILE <path>`
If set, it is used as the --cacert value, naming a CA bundle file. It is
specified to be recognized for every TLS transfer. The trust-anchor loading it
feeds is implemented; the transfers are not, so nothing consumes the value at
present.

## `SSLKEYLOGFILE <path>`
If you set this environment variable to a filename, curl stores TLS secrets
from its connections in that file when invoked to enable you to analyze the
TLS traffic in real time using network analyzing tools such as Wireshark.

**Treat that file as the secret it is.** The key log plus a packet capture is
enough to decrypt every session it covers, offline and at any later date, so it
carries the same weight as the private keys involved. Set the variable only for
the run you are debugging, keep the file on local storage you control, and delete
it when you are done rather than leaving it in a home directory or a shared
temporary directory.

curl enforces part of that for you and refuses to write secrets to a file it
cannot vouch for. A log it creates is created mode `0600`, owner read and write
and nothing for anyone else, and before writing to any file it checks three
things: the path must be a regular file, so a FIFO, socket, device or directory
is refused; it must be owned by the user running curl, since another owner can
read what is written to it; and it must carry no group or other permission bit,
read or write. A file failing any of those is not written to, and the refusal is
silent by design -- nothing is printed and no transfer fails, because a
diagnostic naming the path would itself end up in logs. If you expect a key log
and find none, check those three properties first.

The key log writer this variable drives is delivered in `curl-rs-lib`, and the
one specified TLS implementation supports key logging. The TLS session that
would feed secrets into the log does not run yet, so nothing is written today.

## `USERPROFILE <directory>`
On Windows, this variable is used when trying to find the home directory. If
the other, primary, variables are all unset. If set, curl uses the path
**"$USERPROFILE\Application Data"**.

## `XDG_CONFIG_HOME <directory>`
If *CURL_HOME* is not set, this variable is checked when looking for a
default .curlrc file.
