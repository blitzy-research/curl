<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# PROTOCOLS
curl supports numerous protocols, or put in URL terms: schemes. Your
particular build may not support them all. The sections below are one per
protocol family rather than one per scheme, and between them they cover all 33
schemes curl registers; where a family name is parenthesized, as in FTP(S), the
single section covers every scheme in that family. Transfers are specified for
exactly nine of the 33: `file`, `ftp`, `ftps`, `http`, `https`, `scp`, `sftp`,
`ws` and `wss`. Each of the other 24 registered schemes is specified to be
recognized when curl parses a URL, with a transfer request for one of them
failing with `CURLE_UNSUPPORTED_PROTOCOL`. The `Protocols:` line in the
--version output names only those nine schemes, so read a section below as a
description of the protocol family itself rather than as a claim about what a
given build transfers.
## DICT
Lets you lookup words using online dictionaries.
## FILE
Read or write local files. curl does not support accessing file:// URL
remotely, but when running on Microsoft Windows using the native UNC approach
works. Only absolute paths.
## FTP(S)
curl supports the File Transfer Protocol with a lot of tweaks and levers. With
or without using TLS.
## GOPHER(S)
Retrieve files.
## HTTP(S)
curl supports HTTP with numerous options and variations. It can speak HTTP
version 0.9, 1.0, 1.1, 2 and 3 depending on build options and the correct
command line options.
## IMAP(S)
Using the mail reading protocol, curl can download emails for you. With or
without using TLS.
## LDAP(S)
curl can do directory lookups for you, with or without TLS.
## MQTT
curl supports MQTT version 3. Downloading over MQTT equals subscribing to a
topic while uploading/posting equals publishing on a topic. MQTT over TLS is not
supported (yet).
## POP3(S)
Downloading from a pop3 server means getting an email. With or without using
TLS.
## RTMP(S)
The **Realtime Messaging Protocol** is primarily used to serve streaming media
and curl can download it. This is the largest of the parenthesized families and
registers six schemes rather than two: `rtmp` and `rtmpe` default to port 1935,
`rtmpt` and `rtmpte` default to the HTTP port, and `rtmps` and `rtmpts` default
to the HTTPS port.
## RTSP
curl supports RTSP 1.0 downloads.
## SCP
curl supports SSH version 2 scp transfers.
## SFTP
curl supports SFTP (draft 5) done over SSH version 2.
## SMB(S)
curl supports SMB version 1 for upload and download.
## SMTP(S)
Uploading contents to an SMTP server means sending an email. With or without
TLS.
## TELNET
Fetching a telnet URL starts an interactive session where it sends what it
reads on stdin and outputs what the server sends it.
## TFTP
curl can do TFTP downloads and uploads.
## WS(S)
WebSocket done over HTTP/1. WSS implies that it works over HTTPS.
