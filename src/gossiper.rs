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

use super::gossip::{Gossip, Statistics};
use super::messages::{GossipRpc, Message};
use ed25519_dalek::{Keypair, PublicKey};
use error::Error;
use id::Id;
use maidsafe_utilities::serialisation;
use rand::{self, Rng};
use serde::ser::Serialize;
use sha3::Sha3_512;
use std::fmt::{self, Debug, Formatter};

/// An entity on the network which will gossip messages.
pub struct Gossiper {
    keys: Keypair,
    peers: Vec<Id>,
    gossip: Gossip,
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

    /// Start a new round.  Returns a vector of Push RPCs messages to be sent to the given peers.
    pub fn next_round(&mut self) -> Result<Vec<(Id, Vec<u8>)>, Error> {
        if self.peers.is_empty() {
            return Err(Error::NoPeers);
        }
        let push_list = self.gossip.next_round();
        Ok(
            self.prepare_to_send(push_list)
                .into_iter()
                .map(|message| {
                    // Safe to unwrap here as we return above if self.peers.is_empty() is true.
                    let peer_id = unwrap!(rand::thread_rng().choose(&self.peers));
                    debug!("{:?} Sending Push messages to {:?}", self, peer_id);
                    (*peer_id, message)
                })
                .collect(),
        )
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
        self.gossip.statistics()
    }

    #[cfg(test)]
    /// Clear the statistics and gossip's cache.
    pub fn clear(&mut self) {
        self.gossip.clear();
    }

    fn prepare_to_send(&mut self, rpcs: Vec<GossipRpc>) -> Vec<Vec<u8>> {
        let mut messages = vec![];
        for rpc in rpcs {
            if let Ok(serialised_msg) = Message::serialise(&rpc, &self.keys) {
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
        }
    }
}

impl Debug for Gossiper {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::{self, Itertools};
    use maidsafe_utilities::SeededRng;
    use rand::{self, Rng};
    use std::{cmp, u64};

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

    fn send_messages(gossipers: &mut Vec<Gossiper>, num_of_msgs: u32) -> (u64, u64, Statistics) {
        let mut rng = SeededRng::thread_rng();
        let empty_rpc_len = unwrap!(Message::serialise(
            &GossipRpc::Push {
                msg: vec![],
                counter: 0,
            },
            &gossipers[0].keys,
        )).len();

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

        // Polling
        let mut processed = true;
        while processed {
            processed = false;
            let mut messages = vec![];
            // Call `next_round()` on each node to gather a list of all Push RPCs.
            for gossiper in gossipers.iter_mut() {
                if !rumors.is_empty() && rng.gen() {
                    let rumor = unwrap!(rumors.pop());
                    let _ = gossiper.send_new(&rumor);
                }
                let push_msgs = unwrap!(gossiper.next_round());
                for (dst_id, push_msg) in push_msgs {
                    // Any non-empty Push RPC will have a length more than `empty_rpc_len`.
                    if push_msg.len() > empty_rpc_len {
                        processed = true;
                    }
                    messages.push((gossiper.id(), dst_id, push_msg));
                }
            }

            // Send all Push RPCs and the corresponding Pull RPCs
            for (src_id, dst_id, push_msg) in messages {
                let pull_msgs = unwrap!(gossipers.iter_mut().find(|node| node.id() == dst_id))
                    .handle_received_message(&src_id, &push_msg);
                let mut src = unwrap!(gossipers.iter_mut().find(|node| node.id() == src_id));
                for pull_msg in pull_msgs {
                    assert!(src.handle_received_message(&dst_id, &pull_msg).is_empty());
                }
            }
        }

        let mut statistics = Statistics::default();
        let mut nodes_missed = 0;
        let mut msgs_missed = 0;
        // Checking nodes missed the message, and clear the nodes for the next iteration.
        for gossiper in gossipers.iter_mut() {
            let stat = gossiper.statistics();
            statistics.add(&stat);
            statistics.rounds = stat.rounds;

            if gossiper.messages().len() as u32 != num_of_msgs {
                nodes_missed += 1;
                msgs_missed += u64::from(num_of_msgs - gossiper.messages().len() as u32);
            }
            gossiper.clear();
        }

        // The empty push & pull sent during the last round to confirm the gossiping is completed
        // shall not be included in the statistics.
        statistics.empty_pull_sent -= gossipers.len() as u64;
        statistics.empty_push_sent -= gossipers.len() as u64;

        (nodes_missed, msgs_missed, statistics)
    }

    fn one_message_test(num_of_nodes: u32) {
        let mut gossipers = create_network(num_of_nodes);
        println!("Network of {} nodes:", num_of_nodes);
        let iterations = 1000;
        let mut metrics = Vec::new();
        for _ in 0..iterations {
            metrics.push(send_messages(&mut gossipers, 1));
        }

        let mut metrics_total = Statistics::default();
        let mut metrics_max = Statistics::default();
        let mut metrics_min = Statistics::new_max();
        let mut nodes_missed_total = 0;
        let mut nodes_missed_max = 0;
        let mut nodes_missed_min = u64::MAX;
        let mut msgs_missed_total = 0;
        let mut msgs_missed_max = 0;
        let mut msgs_missed_min = u64::MAX;

        for (nodes_missed, msgs_missed, metric) in metrics {
            nodes_missed_total += nodes_missed;
            nodes_missed_max = cmp::max(nodes_missed_max, nodes_missed);
            nodes_missed_min = cmp::max(nodes_missed_min, nodes_missed);
            msgs_missed_total += msgs_missed;
            msgs_missed_max = cmp::max(msgs_missed_max, msgs_missed);
            msgs_missed_min = cmp::max(msgs_missed_min, msgs_missed);
            metrics_total.add(&metric);
            metrics_max.max(&metric);
            metrics_min.min(&metric);
        }
        println!(
            "    AVERAGE ---- rounds: {}, empty_pulls: {}, empty_pushes: {}, \
             full_msgs_sent: {}, msgs_missed: {}, nodes_missed: {} ({:.2}%)",
            metrics_total.rounds / iterations,
            metrics_total.empty_pull_sent / iterations,
            metrics_total.empty_push_sent / iterations,
            metrics_total.full_message_sent / iterations,
            msgs_missed_total as f64 / iterations as f64,
            nodes_missed_total as f64 / iterations as f64,
            (100 * nodes_missed_total) as f64 / iterations as f64 / f64::from(num_of_nodes)
        );
        print!("    MIN -------- ", );
        print_metric(nodes_missed_min, msgs_missed_min, &metrics_min);
        print!("    MAX -------- ", );
        print_metric(nodes_missed_max, msgs_missed_max, &metrics_max);
    }

    fn print_metric(mut nodes_missed: u64, mut msgs_missed: u64, stat: &Statistics) {
        if nodes_missed == u64::MAX {
            nodes_missed = 0;
            msgs_missed = 0;
        }
        println!(
            "rounds: {}, empty_pulls: {}, empty_pushes: {}, full_msg_sent: {}, \
             msg_missed: {}, nodes_missed: {}",
            stat.rounds,
            stat.empty_pull_sent,
            stat.empty_push_sent,
            stat.full_message_sent,
            msgs_missed,
            nodes_missed
        );
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
                println!(
                    "network having {:?} nodes, gossiping {:?} messages.",
                    nodes,
                    msgs
                );
                let mut gossipers = create_network(*nodes);
                let metric = send_messages(&mut gossipers, *msgs);
                print_metric(metric.0, metric.1, &metric.2);
            }
        }

    }
}
