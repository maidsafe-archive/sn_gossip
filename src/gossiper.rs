// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use ed25519_dalek::Keypair;
use error::Error;
use gossip::Gossip;
use id::Id;
use maidsafe_utilities::serialisation::{self, SerialisationError};
use messages::Message;
use rand::{self, Rng};
use sha3::Sha3_512;
use std::fmt::{self, Debug, Formatter};

/// An entity on the network which will gossip messages.
pub struct Gossiper {
    keys: Keypair,
    peers: Vec<Id>,
    gossip: Gossip,
}

// Push & Pull procedure is defined as:
//      * Node A randomly picks a node B and sends hot_messages and a pull request to B.
//      * When B received the pull request, it sends back its hot_messages + cold_messages
// hot_message is definded as `message_counter <= ln(N)`
// cold_message is defined as `ln(N) < message_counter <= 2ln(N)`
// message_counter got increased each time there is a push_tick.
// when `message_counter > 2ln(N)`, the message is no longer get pushed or pulled to another node.

impl Gossiper {
    /// The ID of this `Gossiper`, i.e. its public key.
    pub fn id(&self) -> Id {
        self.keys.public.into()
    }

    /// Add the ID of another node on the network.  This will fail if `send_new()` has already been
    /// called since this `Gossiper` needs to know about all other nodes in the network before
    /// starting to gossip messages.
    pub fn add_peer(&mut self, peer_id: Id) -> Result<(), Error> {
        if !self.gossip.get_messages().is_empty() {
            return Err(Error::AlreadyStarted);
        }
        let _ = self.peers.push(peer_id);
        self.gossip.add_peer();
        Ok(())
    }

    /// Send a new message starting at this `Gossiper`.
    pub fn send_new(&mut self, message: &str) -> Result<(Id, Vec<Vec<u8>>), Error> {
        if self.peers.is_empty() {
            return Err(Error::NoPeers);
        }
        self.gossip.inform(message.to_string());
        self.push_tick()
    }

    /// Start a push round.
    pub fn push_tick(&mut self) -> Result<(Id, Vec<Vec<u8>>), Error> {
        let peer_id = match rand::thread_rng().choose(&self.peers) {
            Some(id) => *id,
            None => return Err(Error::NoPeers),
        };
        let push_list = self.gossip.get_push_list();
        let mut messages = Vec::new();
        for (count, msg) in push_list {
            let message = Message::Push(count, msg);
            if let Ok(str) = serialisation::serialise(&message) {
                messages.push(str);
            } else {
                println!("Failed to serialise {:?}", message);
            }
        }
        if let Ok(str) = self.pull_tick() {
            messages.push(str);
        } else {
            println!("Failed to serialise Pull request");
        }

        println!("{:?} Sending messages and pull to {:?}", self, peer_id);
        Ok((peer_id, messages))
    }

    /// Start a pull round.
    pub fn pull_tick(&self) -> Result<Vec<u8>, SerialisationError> {
        serialisation::serialise(&Message::Pull)
    }

    /// Handles an incoming message from peer.
    pub fn handle_received_message(&mut self, peer_id: &Id, message: &[u8]) -> Vec<Vec<u8>> {
        println!(
            "{:?} handling message of {} bytes from {:?}",
            self,
            message.len(),
            peer_id
        );
        let msg = if let Ok(msg) = serialisation::deserialise::<Message>(message) {
            msg
        } else {
            println!("Failed to deserialise message");
            return Vec::new();
        };
        let mut response = vec![];
        match msg {
            Message::Push(count, msg) => self.gossip.receive(count, msg),
            Message::Pull => {
                let messages_pushed_to_peer = self.gossip.handle_pull();
                for (count, msg) in messages_pushed_to_peer {
                    println!("{:?} Sending message: {:?} to {:?}", self, msg, peer_id);
                    if let Ok(str) = serialisation::serialise(&Message::Push(count, msg)) {
                        response.push(str);
                    }
                }
            }
        }
        response
    }
}

impl Default for Gossiper {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let keys = Keypair::generate::<Sha3_512>(&mut rng);
        Gossiper {
            keys,
            peers: vec![],
            gossip: Gossip::new(),
        }
    }
}

impl Debug for Gossiper {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self.id())
    }
}
