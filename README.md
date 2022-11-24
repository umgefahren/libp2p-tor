# libp2p-community-tor

Tor based transport for libp2p. Connect through the Tor network to TCP listeners.

## ⚠️ Misuse warning ⚠️ - read carefull before using
Although the sound of "Tor" might convey a sense of security it is *very* easy to misuse this
crate and leaking private information while using. Study libp2p carefully and try to make sure
you fully understand it's current limits regarding privacy. I.e. using identify might already
render this protocol obsolete.

Main entrypoint of the crate: [`TorTransport`]

### Example
```rust
let address = "/dns/www.torproject.org/tcp/1000".parse()?;
let mut transport = libp2p_community_tor::AsyncStdNativeTlsTorTransport::bootstrapped().await?;
// we have achieved tor connection
let _conn = transport.dial(address)?.await?;
```

License: MIT
