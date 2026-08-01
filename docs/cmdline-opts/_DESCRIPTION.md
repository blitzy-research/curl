<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# DESCRIPTION

**curl** is a tool for transferring data from or to a server using URLs. It
is specified to recognize URLs for all 33 of the schemes curl
registers: DICT, FILE, FTP, FTPS, GOPHER, GOPHERS, HTTP, HTTPS, IMAP, IMAPS,
LDAP, LDAPS, MQTT, MQTTS, POP3, POP3S, RTMP, RTMPE, RTMPS, RTMPT, RTMPTE,
RTMPTS, RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET, TFTP, WS and WSS.
Transfers are specified for exactly nine of them: `file`, `ftp`, `ftps`,
`http`, `https`, `scp`, `sftp`, `ws` and `wss`. A transfer request for any of
the other 24 registered schemes is specified to fail with
`CURLE_UNSUPPORTED_PROTOCOL`, and the `Protocols:` line in the --version output
names only those nine. The PROTOCOLS section below describes each scheme.

curl is powered by libcurl for all transfer-related features. See
*libcurl(3)* for details.
