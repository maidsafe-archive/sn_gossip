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

use ed25519_dalek::{Keypair, PUBLIC_KEY_LENGTH};
use error::Error;
use futures::sync::mpsc;
use gossip::Gossip;
use maidsafe_utilities::serialisation;
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
        println!("{:?} Sending new message: {:?}", self, message);
        let _serialised = unwrap!(serialisation::serialise(&message));
        Ok(())
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
