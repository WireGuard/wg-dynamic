# wg-dynamic protocol

The wg-dynamic protocol runs over a reliable and ordered data stream
between a client and a server. Addressing is done on an upper layer,
typically IP.

The protocol consists of ASCII messages with key=value pairs separated
by newline characters. A message ends with two consecutive newline
characters.

The first key=value pair is treated as a command with the key being
the command and the value being the protocol version. The key=value
pairs following the first are arguments to the command.
