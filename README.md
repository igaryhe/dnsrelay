# Simple DNS Relay written in Rust

This project is implemented mainly following EmilHernvall's [dnsguide](https://github.com/EmilHernvall/dnsguide).

Up to now, the program can forward local dns queries to the server, and send back the response to the resolver. Besides, it has a "host" function built in. You can add entries in `dnsrelay.ron`.
