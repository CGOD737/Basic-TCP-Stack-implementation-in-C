# Project 2 

## Developers

tpc.c and tcp_connection.h completed by Chris Godfrey (ctg18) and Diana Kocsis (dlk61)

## How Work was done

Diana worked on active opens while Chris did passive opens. Most of the work was done synchronously via zoom through their screenshare feature.
We were both able to control the screen and work through the testing together. 

## What Works

The handshake protocol is confirmed to work on the active and passive side. We are also able to send data packets and essentially have a conversation between the server and client.

## Explanation of What we did.

For Stop-and-Wait, we added a tracker boolean to the tcp_connection data structure called "stop" that keeps track of when you recieve an ACK. If you do recieve an ACK, that 
number is 0, if you don't, then that number is 1.

Also to keep track of previous ACK and SEQ Numbers, we added two uint32_t variables each called last_seq and last_ack. This is mainly used within the tcp_send outside of the handshake protocol.

## What doesn't Work.

Timeouts have not been implemented. The Closing is also a little buggy but the states are all correct in where we want to go after each case.

## Possible Extra Credit Bug Reports???

For some reason, when we tested the active listen with listen_server, instead of the client getting "Recieved Data" in the response, the client got "cieved data". We don't exactly know what's causing this,
but we checked on wireshark and the full original data buffer was being sent. We don't know why it is exactly showing up like that in the client. However, we don't think that is on our end.

