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
use futures::stream::BoxStream;
use libp2p::multiaddr::Protocol;
use libp2p::{
    core::transport::{ListenerId, TransportEvent},
    Multiaddr, Transport, TransportError,
};
use std::collections::HashMap;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use thiserror::Error;
use tor_hsservice::handle_rend_requests;
use tor_hsservice::status::OnionServiceStatus;
use tor_hsservice::StreamRequest;
use tor_rtcompat::tokio::TokioRustlsRuntime;

// We only need these imports if the `listen-onion-service` feature is enabled
#[cfg(feature = "listen-onion-service")]
use tor_cell::relaycell::msg::{Connected, End, EndReason};
#[cfg(feature = "listen-onion-service")]
use tor_hsservice::{HsId, OnionServiceConfig, RunningOnionService};
#[cfg(feature = "listen-onion-service")]
use tor_proto::stream::IncomingStreamRequest;

mod address;
mod provider;

use address::{dangerous_extract, safe_extract};
pub use provider::TokioTorStream;

pub type TorError = arti_client::Error;

type PendingUpgrade = BoxFuture<'static, Result<TokioTorStream, TorTransportError>>;
#[cfg(feature = "listen-onion-service")]
type OnionServiceStream = BoxStream<'static, StreamRequest>;
#[cfg(feature = "listen-onion-service")]
type OnionServiceStatusStream = BoxStream<'static, OnionServiceStatus>;

/// Struct representing an onion address we are listening on for libp2p connections.
#[cfg(feature = "listen-onion-service")]
struct TorListener {
    #[allow(dead_code)] // We need to own this to keep the RunningOnionService alive
    /// The onion service we are listening on
    service: Arc<RunningOnionService>,
    /// The stream of status updates for the onion service
    status_stream: OnionServiceStatusStream,
    /// The stream incoming [`StreamRequest`]s
    request_stream: OnionServiceStream,

    /// The port we are listening on
    port: u16,
    /// The onion address we are listening on
    onion_address: Multiaddr,
}

/// Mode of address conversion.
/// Refer tor [arti_client::TorAddr](https://docs.rs/arti-client/latest/arti_client/struct.TorAddr.html) for details
#[derive(Debug, Clone, Copy, Hash, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddressConversion {
    /// Uses only DNS for address resolution (default).
    #[default]
    DnsOnly,
    /// Uses IP and DNS for addresses.
    IpAndDns,
}

pub struct TorTransport {
    pub conversion_mode: AddressConversion,

    /// The Tor client.
    client: Arc<TorClient<TokioRustlsRuntime>>,

    /// Onion services we are listening on.
    #[cfg(feature = "listen-onion-service")]
    listeners: HashMap<ListenerId, TorListener>,

    /// Onion services we are running but currently not listening on
    #[cfg(feature = "listen-onion-service")]
    services: Vec<(Arc<RunningOnionService>, OnionServiceStream)>,
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

        Ok(Self::from_client(client, conversion_mode))
    }

    /// Builds a `TorTransport` from an existing Arti `TorClient`.
    pub fn from_client(
        client: Arc<TorClient<TokioRustlsRuntime>>,
        conversion_mode: AddressConversion,
    ) -> Self {
        Self {
            client,
            conversion_mode,
            #[cfg(feature = "listen-onion-service")]
            listeners: HashMap::new(),
            #[cfg(feature = "listen-onion-service")]
            services: Vec::new(),
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

    /// Call this function to instruct the transport to listen on a specific onion address
    /// You need to call this function **before** calling `listen_on`
    ///
    /// # Returns
    /// Returns the Multiaddr of the onion address that the transport can be instructed to listen on
    /// To actually listen on the address, you need to call [`listen_on`] with the returned address
    #[cfg(feature = "listen-onion-service")]
    pub fn add_onion_service(
        &mut self,
        svc_cfg: OnionServiceConfig,
        port: u16,
    ) -> anyhow::Result<Multiaddr> {
        let (service, request_stream) = self.client.launch_onion_service(svc_cfg)?;
        let request_stream = Box::pin(handle_rend_requests(request_stream));

        let multiaddr = service
            .onion_name()
            .ok_or_else(|| anyhow::anyhow!("Onion service has no nickname"))?
            .to_multiaddr(port);

        self.services.push((service, request_stream));

        Ok(multiaddr)
    }
}

#[derive(Debug, Error)]
pub enum TorTransportError {
    #[error(transparent)]
    Client(#[from] TorError),
    #[cfg(feature = "listen-onion-service")]
    #[error(transparent)]
    Service(#[from] tor_hsservice::ClientError),
    #[cfg(feature = "listen-onion-service")]
    #[error("Stream closed before receiving data")]
    StreamClosed,
    #[cfg(feature = "listen-onion-service")]
    #[error("Stream port does not match listener port")]
    StreamPortMismatch,
    #[cfg(feature = "listen-onion-service")]
    #[error("Onion service is broken")]
    Broken,
}

#[cfg(feature = "listen-onion-service")]
trait HsIdExt {
    fn to_multiaddr(&self, port: u16) -> Multiaddr;
}

#[cfg(feature = "listen-onion-service")]
impl HsIdExt for HsId {
    /// Convert an HsId to a Multiaddr
    fn to_multiaddr(&self, port: u16) -> Multiaddr {
        let onion_domain = self.to_string();
        let onion_without_dot_onion = onion_domain
            .split(".")
            .nth(0)
            .expect("Display formatting of HsId to contain .onion suffix");
        let multiaddress_string = format!("/onion3/{}:{}", onion_without_dot_onion, port);

        Multiaddr::from_str(&multiaddress_string)
            .expect("A valid onion address to be convertible to a Multiaddr")
    }
}

trait StatusExt {
    fn is_reachable(&self) -> bool;
    fn is_broken(&self) -> bool;
}

impl StatusExt for OnionServiceStatus {
    /// Returns true if the onion service is reachable
    fn is_reachable(&self) -> bool {
        match self.state() {
            tor_hsservice::status::State::Running => true,
            tor_hsservice::status::State::DegradedReachable => true,
            _ => false,
        }
    }

    fn is_broken(&self) -> bool {
        matches!(self.state(), tor_hsservice::status::State::Broken)
    }
}

impl Transport for TorTransport {
    type Output = TokioTorStream;
    type Error = TorTransportError;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;
    type ListenerUpgrade = PendingUpgrade;

    fn listen_on(
        &mut self,
        id: ListenerId,
        onion_address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        // If the `listen-onion-service` feature is not enabled, immediately return an error
        #[cfg(not(feature = "listen-onion-service"))]
        return Err(TransportError::MultiaddrNotSupported(onion_address.clone()));

        // If the address is not an onion3 address, return an error
        let Some(Protocol::Onion3(address)) = onion_address.into_iter().nth(0) else {
            return Err(TransportError::MultiaddrNotSupported(onion_address.clone()));
        };

        // Find the running onion service that matches the requested address
        // If we find it, remove it from [`services`] and insert it into [`listeners`]

        let position = self
            .services
            .iter()
            .position(|(service, _)| {
                service.onion_name().map_or(false, |name| {
                    name.to_multiaddr(address.port()) == onion_address
                })
            })
            .ok_or_else(|| TransportError::MultiaddrNotSupported(onion_address.clone()))?;

        let (service, request_stream) = self.services.remove(position);

        let status_stream = Box::pin(service.status_events());

        self.listeners.insert(
            id,
            TorListener {
                service,
                request_stream,
                onion_address: onion_address.clone(),
                port: address.port(),
                status_stream,
            },
        );

        return Ok(());
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        // If the `listen-onion-service` feature is not enabled, we do not support listening
        #[cfg(not(feature = "listen-onion-service"))]
        return false;

        // Take the listener out of the map. This will stop listening on onion service for libp2p connections (we will not poll it anymore)
        // However, we will not stop the onion service itself because we might want to reuse it later
        // The onion service will be stopped when the transport is dropped
        if let Some(listener) = self.listeners.remove(&id) {
            self.services
                .push((listener.service, listener.request_stream));
            return true;
        }

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

            Ok(TokioTorStream::from(stream))
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
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        // If the `listen-onion-service` feature is not enabled, we do not support listening
        #[cfg(not(feature = "listen-onion-service"))]
        return Poll::Pending;

        for (listener_id, listener) in self.listeners.iter_mut() {
            // Check if the service has any new statuses
            if let Poll::Ready(Some(status)) = listener.status_stream.as_mut().poll_next(cx) {
                if status.is_reachable() {
                    // TODO: We might report the address here multiple time to the swarm. Is this a problem?
                    return Poll::Ready(TransportEvent::NewAddress {
                        listener_id: *listener_id,
                        listen_addr: listener.onion_address.clone(),
                    });
                }

                if status.is_broken() {
                    return Poll::Ready(TransportEvent::ListenerError {
                        listener_id: *listener_id,
                        error: TorTransportError::Broken,
                    });
                }
            }

            match listener.request_stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(request)) => {
                    let port = listener.port;
                    let upgrade: PendingUpgrade = Box::pin(async move {
                        // Check if the port matches what we expect
                        if let IncomingStreamRequest::Begin(begin) = request.request() {
                            if begin.port() != port {
                                // Reject the connection with CONNECTREFUSED
                                request
                                    .reject(End::new_with_reason(EndReason::CONNECTREFUSED))
                                    .await?;

                                return Err(TorTransportError::StreamPortMismatch);
                            }
                        }

                        // Accept the stream and forward it to the swarm
                        let data_stream = request.accept(Connected::new_empty()).await?;
                        Ok(TokioTorStream::from(data_stream))
                    });

                    return Poll::Ready(TransportEvent::Incoming {
                        listener_id: *listener_id,
                        upgrade,
                        local_addr: listener.onion_address.clone(),
                        send_back_addr: listener.onion_address.clone(),
                    });
                }

                // The stream has ended. Most likely because the service was shut down
                Poll::Ready(None) => {
                    return Poll::Ready(TransportEvent::ListenerClosed {
                        listener_id: *listener_id,
                        reason: Ok(()),
                    });
                }
                Poll::Pending => {}
            }
        }

        Poll::Pending
    }
}
