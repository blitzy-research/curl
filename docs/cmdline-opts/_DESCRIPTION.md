<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# DESCRIPTION

**curl** is a tool for transferring data from or to a server using URLs. It
recognizes URLs for these schemes: DICT, FILE, FTP, FTPS, GOPHER, GOPHERS,
HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, MQTT, MQTTS, POP3, POP3S, RTMP, RTMPS,
RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET, TFTP, WS and WSS. Of the 33
schemes curl registers, this build performs transfers for exactly nine:
`file`, `ftp`, `ftps`, `http`, `https`, `scp`, `sftp`, `ws` and `wss`. A
transfer request for any of the other 24 registered schemes fails with
`CURLE_UNSUPPORTED_PROTOCOL`, and the `Protocols:` line in the --version output
names only those nine. The PROTOCOLS section below describes each scheme.

curl is powered by libcurl for all transfer-related features. See
*libcurl(3)* for details.
