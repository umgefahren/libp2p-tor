[![Continuous integration](https://github.com/umgefahren/libp2p-tor/actions/workflows/ci.yml/badge.svg)](https://github.com/umgefahren/libp2p-tor/actions/workflows/ci.yml)


# libp2p Tor

Tor based transport for libp2p. Connect through the Tor network to TCP listeners.

Build on top of [Arti](https://gitlab.torproject.org/tpo/core/arti).

## ⚠️ Misuse warning ⚠️ - read carefully before using

Although the sound of "Tor" might convey a sense of security it is *very* easy to misuse this
crate and leaking private information while using. Study libp2p carefully and try to make sure
you fully understand it's current limits regarding privacy. I.e. using identify might already
render this transport obsolete.

This transport explicitly **doesn't** provide any enhanced privacy if it's just used like a regular transport.
Use with caution and at your own risk. **Don't** just blindly advertise Tor without fully understanding what you
are dealing with.

### Add to your dependencies

This won't work:
```bash
cargo add libp2p-community-tor@0.1.0-alpha
```

You have to choose a TLS provider **and** a runtime.
The TLS providers are:

- [`rustls`](https://github.com/rustls/rustls)
- [`native-tls`](https://github.com/sfackler/rust-native-tls)

The runtimes are:

- [`tokio`](https://github.com/tokio-rs/tokio)
- [`async-std`](https://github.com/async-rs/async-std)

|               | **rustls**                                                       | **native-tls**                                                       |
|---------------|------------------------------------------------------------------|----------------------------------------------------------------------|
| **tokio**     | `cargo add libp2p-community-tor@0.1.0-alpha -F tokio,rustls`     | `cargo add libp2p-community-tor@0.1.0-alpha -F tokio,native-tls`     |
| **async-std** | `cargo add libp2p-community-tor@0.1.0-alpha -F async-std,rustls` | `cargo add libp2p-community-tor@0.1.0-alpha -F async-std,native-tls` |

### Example
```rust
let address = "/dns/www.torproject.org/tcp/1000".parse()?;
let mut transport = libp2p_community_tor::AsyncStdNativeTlsTorTransport::bootstrapped().await?;
// we have achieved tor connection
let _conn = transport.dial(address)?.await?;
```

### About

This crate originates in a PR to bring Tor support too rust-libp2p. Read more about it here: libp2p/rust-libp2p#2899

License: MIT
