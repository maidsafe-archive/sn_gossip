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

#![allow(dead_code)]

use super::gossip::Gossip;
use super::messages::{GossipRpc, Message};
use ed25519_dalek::{Keypair, PublicKey};
use error::Error;
use id::Id;
use maidsafe_utilities::serialisation;
use rand::{self, Rng};
use serde::ser::Serialize;
use sha3::Sha3_512;
use std::fmt::{self, Debug, Formatter};

#[allow(unused)]
/// An entity on the network which will gossip messages.
pub struct Gossiper {
    keys: Keypair,
    peers: Vec<Id>,
    gossip: Gossip,
    statistics: Statistics,
}

impl Gossiper {
    /// The ID of this `Gossiper`, i.e. its public key.
    pub fn id(&self) -> Id {
        self.keys.public.into()
    }

    /// Add the ID of another node on the network.  This will fail if `send_new()` has already been
    /// called since this `Gossiper` needs to know about all other nodes in the network before
    /// starting to gossip messages.
    pub fn add_peer(&mut self, peer_id: Id) -> Result<(), Error> {
        if !self.gossip.messages().is_empty() {
            return Err(Error::AlreadyStarted);
        }
        self.peers.push(peer_id);
        self.gossip.add_peer();
        Ok(())
    }

    /// Send a new message starting at this `Gossiper`.
    pub fn send_new<T: Serialize>(&mut self, message: &T) -> Result<(), Error> {
        if self.peers.is_empty() {
            return Err(Error::NoPeers);
        }
        self.gossip.new_message(serialisation::serialise(message)?);
        Ok(())
    }

    /// Start a new round.  Returns a vector of Push RPCs messages to be sent to the given peer.
    pub fn next_round(&mut self) -> Result<(Id, Vec<Vec<u8>>), Error> {
        let peer_id = match rand::thread_rng().choose(&self.peers) {
            Some(id) => *id,
            None => return Err(Error::NoPeers),
        };
        self.statistics.rounds += 1;
        let push_list = self.gossip.next_round();
        let messages = self.prepare_to_send(push_list);
        debug!("{:?} Sending Push messages to {:?}", self, peer_id);
        Ok((peer_id, messages))
    }

    /// Handles an incoming message from peer.
    pub fn handle_received_message(&mut self, peer_id: &Id, serialised_msg: &[u8]) -> Vec<Vec<u8>> {
        debug!("{:?} handling message from {:?}", self, peer_id);
        let pub_key = if let Ok(pub_key) = PublicKey::from_bytes(&peer_id.0) {
            pub_key
        } else {
            return Vec::new();
        };
        let rpc = if let Ok(rpc) = Message::deserialise(serialised_msg, &pub_key) {
            rpc
        } else {
            error!("Failed to deserialise message");
            return Vec::new();
        };
        self.statistics.total_full_message_received += 1;
        // If this RPC is a Push from a peer we've not already heard from in this round, there could
        // be a set of Pull responses to be sent back to that peer.
        let responses = self.gossip.receive(*peer_id, rpc);
        self.prepare_to_send(responses)
    }

    /// Returns the list of messages this gossiper has become informed about so far.
    pub fn messages(&self) -> Vec<Vec<u8>> {
        self.gossip.messages()
    }

    /// Returns the statistics of this gossiper.
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }

    #[cfg(test)]
    /// Clear the statistics and gossip's cache.
    pub fn clear(&mut self) {
        self.statistics = Statistics::default();
        self.gossip.clear();
    }

    fn prepare_to_send(&mut self, rpcs: Vec<GossipRpc>) -> Vec<Vec<u8>> {
        let mut messages = vec![];
        for rpc in rpcs {
            if let Ok(serialised_msg) = Message::serialise(&rpc, &self.keys) {
                self.statistics.total_full_message_sent += 1;
                messages.push(serialised_msg);
            } else {
                error!("Failed to serialise {:?}", rpc);
            }
        }
        messages
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
            statistics: Statistics::default(),
        }
    }
}

impl Debug for Gossiper {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self.id())
    }
}

/// Statistics on each gossiper.
#[derive(Clone, Copy, Default)]
pub struct Statistics {
    /// Total rounds experienced (each push_tick is considered as one round).
    pub rounds: u64,
    /// Total pull requests sent from this gossiper.
    pub total_pulls_sent: u64,
    /// Total full message sent from this gossiper.
    pub total_full_message_sent: u64,
    /// Total full message this gossiper received.
    pub total_full_message_received: u64,
}

impl Debug for Statistics {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "rounds: {},  pulls sent: {},  full messages sent: {},  full messages received: {}",
            self.rounds,
            self.total_pulls_sent,
            self.total_full_message_sent,
            self.total_full_message_received
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::{self, Itertools};
    use maidsafe_utilities::SeededRng;
    use rand::{self, Rng};
    use std::{cmp, u64};
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Metrics {
        rounds: u64,
        pulls: u64,
        pushes: u64,
        msgs_missed: u64,
        nodes_missed: u64,
    }

    impl Metrics {
        fn new_max() -> Self {
            Metrics {
                rounds: u64::MAX,
                pulls: u64::MAX,
                pushes: u64::MAX,
                msgs_missed: u64::MAX,
                nodes_missed: u64::MAX,
            }
        }

        fn add(&mut self, other: &Metrics) {
            self.rounds += other.rounds;
            self.pulls += other.pulls;
            self.pushes += other.pushes;
            self.msgs_missed += other.msgs_missed;
            self.nodes_missed += other.nodes_missed;
        }

        fn min(&mut self, other: &Metrics) {
            self.rounds = cmp::min(self.rounds, other.rounds);
            self.pulls = cmp::min(self.pulls, other.pulls);
            self.pushes = cmp::min(self.pushes, other.pushes);
            self.msgs_missed = cmp::min(self.msgs_missed, other.msgs_missed);
            self.nodes_missed = cmp::min(self.nodes_missed, other.nodes_missed);
        }

        fn max(&mut self, other: &Metrics) {
            self.rounds = cmp::max(self.rounds, other.rounds);
            self.pulls = cmp::max(self.pulls, other.pulls);
            self.pushes = cmp::max(self.pushes, other.pushes);
            self.msgs_missed = cmp::max(self.msgs_missed, other.msgs_missed);
            self.nodes_missed = cmp::max(self.nodes_missed, other.nodes_missed);
        }
    }

    impl Debug for Metrics {
        fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
            write!(
                formatter,
                "rounds: {}, pulls: {}, pushes: {}, msgs_missed: {}, nodes_missed: {},",
                self.rounds,
                self.pulls,
                self.pushes,
                self.msgs_missed,
                self.nodes_missed
            )
        }
    }

    fn create_network(node_count: u32) -> Vec<Gossiper> {
        let mut gossipers = itertools::repeat_call(Gossiper::default)
            .take(node_count as usize)
            .collect_vec();
        // Connect all the gossipers.
        for i in 0..(gossipers.len() - 1) {
            let lhs_id = gossipers[i].id();
            for j in (i + 1)..gossipers.len() {
                let rhs_id = gossipers[j].id();
                let _ = gossipers[j].add_peer(lhs_id);
                let _ = gossipers[i].add_peer(rhs_id);
            }
        }
        gossipers
    }

    fn send_messages(gossipers: &mut Vec<Gossiper>, num_of_msgs: u32) -> Metrics {
        let mut rng = SeededRng::thread_rng();

        let mut rumors: Vec<String> = Vec::new();
        for _ in 0..num_of_msgs {
            let raw: Vec<u8> = rng.gen_iter().take(20).collect();
            rumors.push(String::from_utf8_lossy(&raw).to_string());
        }

        // Inform the initial message.
        {
            assert!(num_of_msgs >= 1);
            let gossiper = unwrap!(rand::thread_rng().choose_mut(gossipers));
            let rumor = unwrap!(rumors.pop());
            let _ = gossiper.send_new(&rumor);
        }

        let mut metrics = Metrics::default();

        // Polling
        let mut processed = true;
        while processed {
            processed = false;
            metrics.rounds += 1;
            let mut messages = BTreeMap::new();
            for gossiper in gossipers.iter_mut() {
                if !rumors.is_empty() && rng.gen() {
                    let rumor = unwrap!(rumors.pop());
                    let _ = gossiper.send_new(&rumor);
                }
                let (dst, msgs) = unwrap!(gossiper.next_round());
                metrics.pushes += msgs.len() as u64;
                // The empty Push results a message with length of 13.
                // To avoid parsing the message, here use a hard coded message length to detect
                // whether there is valid message copy to be exchanged.
                if msgs.iter().any(|msg| msg.len() > 13) {
                    processed = true;
                }
                let _ = messages.insert((gossiper.id(), dst), msgs);
            }
            let mut has_response = true;
            while has_response {
                has_response = false;
                let mut responses = BTreeMap::new();
                for ((src, dst), msgs) in messages {
                    let mut target = unwrap!(gossipers.iter_mut().find(|g| g.id() == dst));
                    let mut result = Vec::new();
                    for msg in msgs {
                        result.extend(target.handle_received_message(&src, &msg));
                    }
                    if !result.is_empty() {
                        has_response = true;
                    }
                    metrics.pulls += result.len() as u64;
                    let _ = responses.insert((dst, src), result);
                }
                messages = responses;
            }
        }

        // Checking nodes missed the message, and clear the nodes for the next iteration.
        for gossiper in gossipers.iter_mut() {
            if gossiper.messages().len() as u32 != num_of_msgs {
                metrics.nodes_missed += 1;
                metrics.msgs_missed += u64::from(num_of_msgs - gossiper.messages().len() as u32);
            }
            gossiper.clear();
        }
        metrics
    }

    fn one_message_test(num_of_nodes: u32) {
        let mut gossipers = create_network(num_of_nodes);
        println!("network having {:?} nodes", num_of_nodes);
        let iterations = 1000;
        let mut metrics = Vec::new();
        for _ in 0..iterations {
            metrics.push(send_messages(&mut gossipers, 1))
        }

        let mut metrics_total = Metrics::default();
        let mut metrics_max = Metrics::default();
        let mut metrics_min = Metrics::new_max();
        for metric in &metrics {
            metrics_total.add(metric);
            metrics_max.max(metric);
            metrics_min.min(metric);
        }
        println!(
            "AVERAGE -- rounds: {}, pulls: {}, pushes: {}, msgs_missed: {}, nodes_missed: {}",
            metrics_total.rounds / iterations,
            metrics_total.pulls / iterations,
            metrics_total.pushes / iterations,
            metrics_total.msgs_missed as f64 / iterations as f64,
            metrics_total.nodes_missed as f64 / iterations as f64
        );
        println!("MIN -- {:?}", metrics_min);
        println!("MAX -- {:?}", metrics_max);
    }

    #[test]
    fn one_message() {
        one_message_test(20);
        one_message_test(200);
        one_message_test(2000);
    }

    #[test]
    fn multiple_messages() {
        let num_of_nodes: Vec<u32> = vec![20, 200, 2000];
        let num_of_msgs: Vec<u32> = vec![10, 100, 1000];
        for nodes in &num_of_nodes {
            for msgs in &num_of_msgs {
                let mut gossipers = create_network(*nodes);
                println!(
                    "network having {:?} nodes, gossipping {:?} messages. \n    {:?}",
                    nodes,
                    msgs,
                    send_messages(&mut gossipers, *msgs)
                );
            }
        }

    }
}
