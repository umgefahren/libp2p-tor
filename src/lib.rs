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
//! ## Runtime
//!
//! This crate uses tokio with rustls for its runtime and TLS implementation.
//! No other combinations are supported.
//!
//! ## Example
//! ```no_run
//! use libp2p::core::Transport;
//! # async fn test_func() -> Result<(), Box<dyn std::error::Error>> {
//! let address = "/dns/www.torproject.org/tcp/1000".parse()?;
//! let mut transport = libp2p_community_tor::TorTransport::bootstrapped().await?;
//! // we have achieved tor connection
//! let _conn = transport.dial(address)?.await?;
//! # Ok(())
//! # }
//! # tokio_test::block_on(test_func());
//! ```

use arti_client::{TorClient, TorClientBuilder};
use futures::future::BoxFuture;
use libp2p::{
    core::transport::{ListenerId, TransportEvent},
    Multiaddr, Transport, TransportError,
};
use std::sync::Arc;
use tor_rtcompat::tokio::TokioRustlsRuntime;

mod address;
mod provider;

use address::{dangerous_extract, safe_extract};
pub use provider::TokioTorStream;

pub type TorError = arti_client::Error;

#[derive(Clone)]
pub struct TorTransport {
    // client is in an Arc, because without it the [`Transport::dial`] method can't be implemented,
    // due to lifetime issues. With the, eventual, stabilization of static async traits this issue
    // will be resolved.
    client: Arc<TorClient<TokioRustlsRuntime>>,
    /// The used conversion mode to resolve addresses. One probably shouldn't access this directly.
    /// The usage of [`TorTransport::with_address_conversion`] at construction is recommended.
    pub conversion_mode: AddressConversion,
}

/// Mode of address conversion.
/// Refer tor [arti_client::TorAddr](https://docs.rs/arti-client/latest/arti_client/struct.TorAddr.html) for details
#[derive(Debug, Clone, Copy, Hash, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddressConversion {
    /// Uses only dns for address resolution (default).
    #[default]
    DnsOnly,
    /// uses ip and dns for addresses
    IpAndDns,
}

impl TorTransport {
    /// Creates a new `TorClientBuilder`.
    ///
    /// # Panics
    /// Panics if the current runtime is not a `TokioRustlsRuntime`.
    pub fn builder() -> TorClientBuilder<TokioRustlsRuntime> {
        let runtime =
            TokioRustlsRuntime::current().expect("Couldn't get the current tokio rustls runtime");
        TorClient::with_runtime(runtime)
    }

    /// Creates a bootstrapped `TorTransport`
    ///
    /// # Errors
    /// Could return error emitted during Tor bootstrap by Arti.
    pub async fn bootstrapped() -> Result<Self, TorError> {
        let builder = Self::builder();
        let ret = Self::from_builder(&builder, AddressConversion::DnsOnly)?;
        ret.bootstrap().await?;
        Ok(ret)
    }

    /// Builds a `TorTransport` from an Arti `TorClientBuilder` but does not bootstrap it.
    ///
    /// # Errors
    /// Could return error emitted during creation of the `TorClient`.
    pub fn from_builder(
        builder: &TorClientBuilder<TokioRustlsRuntime>,
        conversion_mode: AddressConversion,
    ) -> Result<Self, TorError> {
        let client = Arc::new(builder.create_unbootstrapped()?);

        Ok(Self {
            client,
            conversion_mode,
        })
    }

    /// Builds a `TorTransport` from an existing Arti `TorClient`.
    pub fn from_client(
        client: Arc<TorClient<TokioRustlsRuntime>>,
        conversion_mode: AddressConversion,
    ) -> Self {
        Self {
            client,
            conversion_mode,
        }
    }

    /// Bootstraps the `TorTransport` into the Tor network.
    ///
    /// # Errors
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

impl Transport for TorTransport {
    type Output = TokioTorStream;
    type Error = TorError;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;
    type ListenerUpgrade = futures::future::Pending<Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        _id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        // although this address might be supported, this is returned in order to not provoke an
        // error when trying to listen on this transport.
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn remove_listener(&mut self, _id: ListenerId) -> bool {
        false
    }

    fn dial(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        let maybe_tor_addr = match self.conversion_mode {
            AddressConversion::DnsOnly => safe_extract(&addr),
            AddressConversion::IpAndDns => dangerous_extract(&addr),
        };

        let tor_address =
            maybe_tor_addr.ok_or(TransportError::MultiaddrNotSupported(addr.clone()))?;
        let onion_client = self.client.clone();

        Ok(Box::pin(async move {
            let stream = onion_client.connect(tor_address).await?;

            tracing::debug!(%addr, "Established connection to peer through Tor");

            Ok(stream.into())
        }))
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
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        // pending is returned here because this transport doesn't support listening, yet
        std::task::Poll::Pending
    }
}
