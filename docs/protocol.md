# wg-dynamic protocol

This document describes version 1 of the wg-dynamic protocol.

The wg-dynamic protocol runs over a reliable and ordered data stream
between a client and a server. Addressing is done on an upper layer,
typically IP.

Clients send a request message to a server and the server responds
with a response message.

Messages are ASCII text with key=value pairs separated by newline
characters. A message ends with two consecutive newline characters.

The first key=value pair is treated as a command with the key being
the command and the value being the protocol version. The key=value
pairs following the first pair are command attributes. The command in
a response matches the command of the request it's a response to.
