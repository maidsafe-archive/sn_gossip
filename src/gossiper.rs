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

use ed25519_dalek::{Keypair, PUBLIC_KEY_LENGTH, PublicKey};
use error::Error;
use futures::sync::mpsc;
use gossip::Gossip;
use maidsafe_utilities::serialisation;
use messages::Message;
use rand;
use sha3::Sha3_512;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};
use std::net::{SocketAddr, ToSocketAddrs};
use std::rc::Rc;

/// An entity on the network which will gossip messages.
pub struct Gossiper {
    keys: Keypair,
    peers: Rc<RefCell<HashMap<SocketAddr, mpsc::UnboundedSender<String>>>>,
    gossip: Gossip,
}

// Push & Pull procedure is defined as:
//      * Node A randomly picks a node B and sends its hot_msg_hash_list to B.
//      * When B received that list, it responds with msg_had_hash_list (containing those message
//        hashes that B already had but be listed in the hot_msg_hash_list) and
//        msg_peer_may_need_hash_list (containing those message hashes that B had in its
//        hot_message_list but not listed in the hot_msg_hash_list).
//      * When A received msg_had_hash_list, it removes those messages from the hot_message_list,
//        and send all the remaining hot messages to node B.
//      * When A received msg_peer_may_need_hash_list, it responds to B with msg_I_need_hash_list,
//        which contains the message hashes that A doesn’t have but listed in the
//        msg_peer_may_need_hash_list.
//      * When B received a message from A, it put it as hot.
//      * When B received msg_I_need_hash_list from A, it sends the requested messages to A.

impl Gossiper {
    /// The ID of this `Gossiper`, i.e. its public key.
    pub fn id(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.keys.public.as_bytes()
    }

    /// Connect to another node on the network.  This will fail if `send_new()` has already been
    /// called since this `Gossiper` needs to connect to all other nodes in the network before
    /// starting to gossip messages.
    pub fn connect<A: ToSocketAddrs>(&mut self, _address: A) -> Result<(), Error> {
        if !self.gossip.get_messages().is_empty() {
            return Err(Error::AlreadyStarted);
        }
        let (_sender, _receiver) = mpsc::unbounded::<String>();
        // self.peers.borrow_mut().insert(addr, sender);
        Ok(())
    }

    /// Send a new message starting at this `Gossiper`.
    pub fn send_new(&mut self, message: &str) -> Result<(), Error> {
        if self.peers.borrow().is_empty() {
            return Err(Error::NoPeers);
        }
        self.gossip.inform_or_receive(message.to_string());
        self.push_tick();
        Ok(())
    }

    /// Start a push round.
    pub fn push_tick(&self) {
        let push_list = self.gossip.get_hot_msg_hash_list();
        println!("{:?} Sending push_list: {:?}", self, push_list);
        let _serialised = unwrap!(serialisation::serialise(&Message::Push(push_list)));
    }

    /// Handles an incoming message from peer.
    pub fn handle_received_message(&mut self, peer: &PublicKey, msg: Message) {
        match msg {
            Message::Message(msg) => self.gossip.inform_or_receive(msg),
            Message::Push(hash_list) => {
                let (already_had_msg_hash_list, peer_may_need_msg_hash_list) =
                    self.gossip.handle_push(&hash_list);
                println!(
                    "{:?} sending (already_had_msg_hash_list, peer_may_need_msg_hash_list) \
                          ({:?}, {:?}) to {:?}",
                    self,
                    already_had_msg_hash_list,
                    peer_may_need_msg_hash_list,
                    peer
                );
                let _serialised = unwrap!(serialisation::serialise(&Message::PushResponse {
                    already_had_msg_hash_list: already_had_msg_hash_list,
                    peer_may_need_msg_hash_list: peer_may_need_msg_hash_list,
                }));
            }
            Message::PushResponse {
                already_had_msg_hash_list,
                peer_may_need_msg_hash_list,
            } => {
                let (messages_pushed_to_peer, messages_i_need) = self.gossip.handle_push_response(
                    &already_had_msg_hash_list,
                    &peer_may_need_msg_hash_list,
                );
                for message in messages_pushed_to_peer {
                    println!("{:?} Sending message: {:?} to {:?}", self, message, peer);
                    let _serialised = unwrap!(serialisation::serialise(&Message::Message(message)));
                }
                println!(
                    "{:?} Sending messages_i_need: {:?} to {:?}",
                    self,
                    messages_i_need,
                    peer
                );
                let _serialised =
                    unwrap!(serialisation::serialise(&Message::Pull(messages_i_need)));
            }
            Message::Pull(hash_list) => {
                let messages_pushed_to_peer = self.gossip.handle_pull(&hash_list);
                for message in messages_pushed_to_peer {
                    println!("{:?} Sending message: {:?} to {:?}", self, message, peer);
                    let _serialised = unwrap!(serialisation::serialise(&Message::Message(message)));
                }
            }
        }
    }
}

impl Default for Gossiper {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let keys = Keypair::generate::<Sha3_512>(&mut rng);
        Gossiper {
            keys,
            peers: Rc::new(RefCell::new(HashMap::new())),
            gossip: Gossip::new(),
        }
    }
}

impl Debug for Gossiper {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "{:02x}{:02x}{:02x}..",
            self.id()[0],
            self.id()[1],
            self.id()[2]
        )
    }
}
