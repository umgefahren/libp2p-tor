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

//! Ping-Onion example
//!
//! See ../src/tutorial.rs for a step-by-step guide building the example below.
//!
//! This example requires two seperate computers, one of which has to be reachable from the
//! internet.
//!
//! On the first computer run:
//! ```sh
//! cargo run --example ping
//! ```
//!
//! It will print the PeerId and the listening addresses, e.g. `Listening on
//! "/ip4/0.0.0.0/tcp/24915"`
//!
//! Make sure that the first computer is reachable under one of these ip addresses and port.
//!
//! On the second computer run:
//! ```sh
//! cargo run --example ping-onion -- /ip4/123.45.67.89/tcp/24915
//! ```
//!
//! The two nodes establish a connection, negotiate the ping protocol
//! and begin pinging each other over Tor.

use futures::StreamExt;
use libp2p::core::upgrade::Version;
use libp2p::Transport;
use libp2p::{
    core::muxing::StreamMuxerBox,
    identity, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    yamux, Multiaddr, PeerId, SwarmBuilder,
};
use libp2p_community_tor::{AddressConversion, TorTransport};
use std::error::Error;

async fn onion_transport(
    keypair: identity::Keypair,
) -> Result<
    libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>,
    Box<dyn Error>,
> {
    let transport = TorTransport::bootstrapped()
        .await?
        .with_address_conversion(AddressConversion::IpAndDns)
        .boxed();

    let auth_upgrade = noise::Config::new(&keypair)?;
    let multiplex_upgrade = yamux::Config::default();

    let transport = transport
        .upgrade(Version::V1)
        .authenticate(auth_upgrade)
        .multiplex(multiplex_upgrade)
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed();

    Ok(transport)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    println!("Local peer id: {local_peer_id}");

    let transport = onion_transport(local_key).await?;

    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            Default::default(),
            (libp2p::tls::Config::new, libp2p::noise::Config::new),
            libp2p::yamux::Config::default,
        )
        .unwrap()
        .with_other_transport(|_| transport)
        .unwrap()
        .with_behaviour(|_| Behaviour {
            ping: libp2p::ping::Behaviour::default(),
        })
        .unwrap()
        .build();

    // Tell the swarm to listen on all interfaces and a random, OS-assigned
    // port.
    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();

    // Dial the peer identified by the multi-address given as the second
    // command-line argument, if any.
    if let Some(addr) = std::env::args().nth(1) {
        let remote: Multiaddr = addr.parse()?;
        swarm.dial(remote)?;
        println!("Dialed {addr}")
    }

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished {
                endpoint, peer_id, ..
            } => {
                println!("Connection established with {peer_id} on {endpoint:?}");
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                println!("Outgoing connection error with {peer_id:?}: {error:?}");
            }
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
            SwarmEvent::Behaviour(event) => println!("{event:?}"),
            _ => {}
        }
    }
}

/// Our network behaviour.
#[derive(NetworkBehaviour)]
struct Behaviour {
    ping: libp2p::ping::Behaviour,
}
