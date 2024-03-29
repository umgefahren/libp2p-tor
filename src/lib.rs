// Copyright 2022 Hannes Furmans
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![warn(clippy::pedantic)]
#![deny(unsafe_code)]
//! Tor based transport for libp2p. Connect through the Tor network to TCP listeners.
//!
//! # ⚠️ Misuse warning ⚠️ - read carefully before using
//! Although the sound of "Tor" might convey a sense of security it is *very* easy to misuse this
//! crate and leaking private information while using. Study libp2p carefully and try to make sure
//! you fully understand it's current limits regarding privacy. I.e. using identify might already
//! render this transport obsolete.
//!
//! This transport explicitly **doesn't** provide any enhanced privacy if it's just used like a regular transport.
//! Use with caution and at your own risk. **Don't** just blindly advertise Tor without fully understanding what you
//! are dealing with.
//!
//! Main entrypoint of the crate: [`TorTransport`]
//!
//! ## Features
//!
//! You have to enable a TLS provider **and** a runtime.
//! The TLS providers are:
//!
//! - [`rustls`](https://github.com/rustls/rustls)
//! - [`native-tls`](https://github.com/sfackler/rust-native-tls)
//!
//! The runtimes are:
//!
//! - [`tokio`](https://github.com/tokio-rs/tokio)
//! - [`async-std`](https://github.com/async-rs/async-std)
//!
//! With that the transports you have to use are:
//!
//! |               | **rustls**                     | **native-tls**                    |
//! |---------------|--------------------------------|-----------------------------------|
//! | **tokio**     | [`TokioRustlsTorTransport`]    | [`TokioNativeTlsTorTransport`]    |
//! | **async-std** | [`AsyncStdRustlsTorTransport`] | [`AsyncStdNativeTlsTorTransport`] |
//!
//! ## Example (async-std + native-tls)
//! ```no_run
//! # use async_std_crate as async_std;
//! # use libp2p_core::Transport;
//! # async fn test_func() -> Result<(), Box<dyn std::error::Error>> {
//! let address = "/dns/www.torproject.org/tcp/1000".parse()?;
//! let mut transport = libp2p_community_tor::AsyncStdNativeTlsTorTransport::bootstrapped().await?;
//! // we have achieved tor connection
//! let _conn = transport.dial(address)?.await?;
//! # Ok(())
//! # }
//! # async_std::task::block_on(async { test_func().await.unwrap() });
//! ```

use address::{dangerous_extract, safe_extract};
use arti_client::{TorClient, TorClientBuilder};
use futures::{future::BoxFuture, FutureExt};
use libp2p_core::{transport::TransportError, Multiaddr, Transport};
use provider::TorStream;
use std::sync::Arc;
use std::{marker::PhantomData, pin::Pin};
use tor_rtcompat::Runtime;

mod address;
mod provider;

#[cfg(feature = "tokio")]
#[doc(inline)]
pub use provider::TokioTorStream;

#[cfg(feature = "async-std")]
#[doc(inline)]
pub use provider::AsyncStdTorStream;

pub type TorError = arti_client::Error;

#[derive(Clone)]
pub struct TorTransport<R: Runtime, S> {
    // client is in an Arc, because without it the [`Transport::dial`] method can't be implemented,
    // due to lifetime issues. With the, eventual, stabilization of static async traits this issue
    // will be resolved.
    client: Arc<TorClient<R>>,
    /// The used conversion mode to resolve addresses. One probably shouldn't access this directly.
    /// The usage of [TorTransport::with_address_conversion] at construction is recommended.
    pub conversion_mode: AddressConversion,
    phantom: PhantomData<S>,
}

/// Configure the onion transport from here.
pub type TorBuilder<R> = TorClientBuilder<R>;

/// Mode of address conversion. Refer tor [arti_client::TorAddr](https://docs.rs/arti-client/latest/arti_client/struct.TorAddr.html) for details.
#[derive(Debug, Clone, Copy, Hash, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddressConversion {
    /// Uses only dns for address resolution (default).
    #[default]
    DnsOnly,
    /// uses ip and dns for addresses
    IpAndDns,
}

impl<R: Runtime, S> TorTransport<R, S> {
    /// Builds a `TorTransport` from an Arti `TorClientBuilder`.
    ///
    /// # Errors
    ///
    /// Could return errors emitted from Arti.
    pub fn from_builder(
        builder: TorBuilder<R>,
        conversion_mode: AddressConversion,
    ) -> Result<Self, TorError> {
        let client = Arc::new(builder.create_unbootstrapped()?);
        Ok(Self {
            client,
            conversion_mode,
            phantom: PhantomData::default(),
        })
    }

    /// Bootstraps the `TorTransport` into the Tor network.
    ///
    /// # Errors
    ///
    /// Could return error emitted during bootstrap by Arti.
    pub async fn bootstrap(&self) -> Result<(), TorError> {
        self.client.bootstrap().await
    }

    /// Set the address conversion mode
    #[must_use]
    pub fn with_address_conversion(mut self, conversion_mode: AddressConversion) -> Self {
        self.conversion_mode = conversion_mode;
        self
    }
}

#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio")
))]
macro_rules! default_constructor {
    () => {
        /// Creates a bootstrapped `TorTransport`
        ///
        /// # Errors
        ///
        /// Could return error emitted during Tor bootstrap by Arti.
        pub async fn bootstrapped() -> Result<Self, TorError> {
            let builder = Self::builder();
            let ret = Self::from_builder(builder, AddressConversion::DnsOnly)?;
            ret.bootstrap().await?;
            Ok(ret)
        }
    };
}

#[cfg(all(feature = "native-tls", feature = "async-std"))]
impl<S> TorTransport<tor_rtcompat::async_std::AsyncStdNativeTlsRuntime, S> {
    pub fn builder() -> TorBuilder<tor_rtcompat::async_std::AsyncStdNativeTlsRuntime> {
        let runtime = tor_rtcompat::async_std::AsyncStdNativeTlsRuntime::current()
            .expect("Couldn't get the current async_std native-tls runtime");
        TorClient::with_runtime(runtime)
    }
    default_constructor!();
}

#[cfg(all(feature = "rustls", feature = "async-std"))]
impl<S> TorTransport<tor_rtcompat::async_std::AsyncStdRustlsRuntime, S> {
    pub fn builder() -> TorBuilder<tor_rtcompat::async_std::AsyncStdRustlsRuntime> {
        let runtime = tor_rtcompat::async_std::AsyncStdRustlsRuntime::current()
            .expect("Couldn't get the current async_std rustls runtime");
        TorClient::with_runtime(runtime)
    }
    default_constructor!();
}

#[cfg(all(feature = "native-tls", feature = "tokio"))]
impl<S> TorTransport<tor_rtcompat::tokio::TokioNativeTlsRuntime, S> {
    pub fn builder() -> TorBuilder<tor_rtcompat::tokio::TokioNativeTlsRuntime> {
        let runtime = tor_rtcompat::tokio::TokioNativeTlsRuntime::current()
            .expect("Couldn't get the current tokio native-tls runtime");
        TorClient::with_runtime(runtime)
    }
    default_constructor!();
}

#[cfg(all(feature = "rustls", feature = "tokio"))]
impl<S> TorTransport<tor_rtcompat::tokio::TokioRustlsRuntime, S> {
    pub fn builder() -> TorBuilder<tor_rtcompat::tokio::TokioRustlsRuntime> {
        let runtime = tor_rtcompat::tokio::TokioRustlsRuntime::current()
            .expect("Couldn't get the current tokio rustls runtime");
        TorClient::with_runtime(runtime)
    }
    default_constructor!();
}

#[cfg(all(feature = "native-tls", feature = "async-std"))]
pub type AsyncStdNativeTlsTorTransport =
    TorTransport<tor_rtcompat::async_std::AsyncStdNativeTlsRuntime, AsyncStdTorStream>;
#[cfg(all(feature = "rustls", feature = "async-std"))]
pub type AsyncStdRustlsTorTransport =
    TorTransport<tor_rtcompat::async_std::AsyncStdRustlsRuntime, AsyncStdTorStream>;
#[cfg(all(feature = "native-tls", feature = "tokio"))]
pub type TokioNativeTlsTorTransport =
    TorTransport<tor_rtcompat::tokio::TokioNativeTlsRuntime, TokioTorStream>;
#[cfg(all(feature = "rustls", feature = "tokio"))]
pub type TokioRustlsTorTransport =
    TorTransport<tor_rtcompat::tokio::TokioRustlsRuntime, TokioTorStream>;

#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysErrorListenerUpgrade<S>(PhantomData<S>);

impl<S> core::future::Future for AlwaysErrorListenerUpgrade<S> {
    type Output = Result<S, TorError>;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        panic!("onion services are not implented yet, since arti doesn't support it. (awaiting Arti 1.2.0)")
    }
}

impl<R: Runtime, S> Transport for TorTransport<R, S>
where
    S: TorStream,
{
    type Output = S;
    type Error = TorError;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;
    type ListenerUpgrade = AlwaysErrorListenerUpgrade<Self::Output>;

    /// Always returns `TransportError::MultiaddrNotSupported`
    fn listen_on(
        &mut self,
        addr: libp2p_core::Multiaddr,
    ) -> Result<
        libp2p_core::transport::ListenerId,
        libp2p_core::transport::TransportError<Self::Error>,
    > {
        // although this address might be supported, this is returned in order to not provoke an
        // error when trying to listen on this transport.
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn remove_listener(&mut self, _id: libp2p_core::transport::ListenerId) -> bool {
        false
    }

    fn dial(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        let maybe_tor_addr = match self.conversion_mode {
            AddressConversion::DnsOnly => safe_extract(&addr),
            AddressConversion::IpAndDns => dangerous_extract(&addr),
        };

        let tor_address = maybe_tor_addr.ok_or(TransportError::MultiaddrNotSupported(addr))?;
        let onion_client = self.client.clone();

        Ok(async move { onion_client.connect(tor_address).await.map(S::from) }.boxed())
    }

    fn dial_as_listener(
        &mut self,
        addr: Multiaddr,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.dial(addr)
    }

    fn address_translation(&self, _listen: &Multiaddr, _observed: &Multiaddr) -> Option<Multiaddr> {
        None
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<libp2p_core::transport::TransportEvent<Self::ListenerUpgrade, Self::Error>>
    {
        // pending is returned here because this transport doesn't support listening
        std::task::Poll::Pending
    }
}
