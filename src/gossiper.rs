// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::gossip::{Gossip, Statistics};
use super::messages::{GossipType, Message};
use crate::error::Error;
use crate::id::Id;
use bincode::serialize;
use ed25519_dalek::{Keypair, PublicKey};
use rand::seq::SliceRandom;
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
        self.gossip.new_message(serialize(message)?);
        Ok(())
    }

    /// Start a new round.  Returns a vector of Push RPCs messages to be sent to the given peer.
    ///
    /// These should all be given to just a single peer to avoid triggering a flood of Pull RPCs in
    /// response.  For example, if we have 100 Push RPCs to send here and we send them all to a
    /// single peer, we only receive a single tranche of Pull RPCs in responses (the tranche
    /// comprising several messages).  However, if we send each Push RPC to a different peer, we'd
    /// receive 100 tranches of Pull RPCs.
    pub fn next_round(&mut self) -> Result<(Id, Vec<Vec<u8>>), Error> {
        let mut rng = rand::thread_rng();
        let peer_id = match self.peers.choose(&mut rng) {
            Some(id) => *id,
            None => return Err(Error::NoPeers),
        };
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

    fn prepare_to_send(&mut self, rpcs: Vec<GossipType>) -> Vec<Vec<u8>> {
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
        let keys = Keypair::generate::<Sha3_512, _>(&mut rng);
        Gossiper {
            keys,
            peers: vec![],
            gossip: Gossip::new(),
        }
    }
}

impl Debug for Gossiper {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use rand::seq::SliceRandom;
    use rand::{self, Rng};
    use std::collections::BTreeMap;
    use std::{cmp, u64};

    fn create_network(node_count: u32) -> Vec<Gossiper> {
        let mut gossipers = std::iter::repeat_with(Gossiper::default)
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
        let mut rng = rand::thread_rng();
        let empty_rpc_len = unwrap!(Message::serialise(
            &GossipType::Push {
                msg: vec![],
                counter: 0,
            },
            &gossipers[0].keys,
        ))
        .len();

        let mut rumors: Vec<String> = Vec::new();
        for _ in 0..num_of_msgs {
            let mut raw = [0u8; 20];
            rng.fill(&mut raw[..]);
            rumors.push(String::from_utf8_lossy(&raw).to_string());
        }

        // Inform the initial message.
        {
            assert!(num_of_msgs >= 1);
            let gossiper = unwrap!(gossipers.choose_mut(&mut rng));
            let rumor = unwrap!(rumors.pop());
            let _ = gossiper.send_new(&rumor);
        }

        // Polling
        let mut processed = true;
        while processed {
            processed = false;
            let mut messages = BTreeMap::new();
            // Call `next_round()` on each node to gather a list of all Push RPCs.
            for gossiper in gossipers.iter_mut() {
                if !rumors.is_empty() && rng.gen() {
                    let rumor = unwrap!(rumors.pop());
                    let _ = gossiper.send_new(&rumor);
                }
                let (dst_id, push_msgs) = unwrap!(gossiper.next_round());
                // Any non-empty Push RPC will have a length more than `empty_rpc_len`.
                if push_msgs.iter().any(|msg| msg.len() > empty_rpc_len) {
                    processed = true;
                }
                let _ = messages.insert((gossiper.id(), dst_id), push_msgs);
            }

            // Send all Push RPCs and the corresponding Pull RPCs.
            for ((src_id, dst_id), push_msgs) in messages {
                let mut pull_msgs = vec![];
                {
                    let dst = unwrap!(gossipers.iter_mut().find(|node| node.id() == dst_id));
                    // Only the first Push from this peer should return any Pulls.
                    for (index, push_msg) in push_msgs.into_iter().enumerate() {
                        if index == 0 {
                            pull_msgs = dst.handle_received_message(&src_id, &push_msg);
                        } else {
                            assert!(dst.handle_received_message(&src_id, &push_msg).is_empty());
                        }
                    }
                }
                let src = unwrap!(gossipers.iter_mut().find(|node| node.id() == src_id));
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

        let mut stats_avg = Statistics::default();
        let mut stats_max = Statistics::default();
        let mut stats_min = Statistics::new_max();
        let mut nodes_missed_avg = 0.0;
        let mut nodes_missed_max = 0;
        let mut nodes_missed_min = u64::MAX;
        let mut msgs_missed_avg = 0.0;
        let mut msgs_missed_max = 0;
        let mut msgs_missed_min = u64::MAX;

        for (nodes_missed, msgs_missed, stats) in metrics {
            nodes_missed_avg += nodes_missed as f64;
            nodes_missed_max = cmp::max(nodes_missed_max, nodes_missed);
            nodes_missed_min = cmp::min(nodes_missed_min, nodes_missed);
            msgs_missed_avg += msgs_missed as f64;
            msgs_missed_max = cmp::max(msgs_missed_max, msgs_missed);
            msgs_missed_min = cmp::min(msgs_missed_min, msgs_missed);
            stats_avg.add(&stats);
            stats_max.max(&stats);
            stats_min.min(&stats);
        }
        nodes_missed_avg /= iterations as f64;
        msgs_missed_avg /= iterations as f64;
        stats_avg.rounds /= iterations;
        stats_avg.empty_pull_sent /= iterations;
        stats_avg.empty_push_sent /= iterations;
        stats_avg.full_message_sent /= iterations;
        stats_avg.full_message_received /= iterations;

        print!("    AVERAGE ---- ");
        print_metric(
            nodes_missed_avg,
            msgs_missed_avg,
            &stats_avg,
            num_of_nodes,
            1,
        );
        print!("    MIN -------- ");
        print_metric(
            nodes_missed_min as f64,
            msgs_missed_min as f64,
            &stats_min,
            num_of_nodes,
            1,
        );
        print!("    MAX -------- ");
        print_metric(
            nodes_missed_max as f64,
            msgs_missed_max as f64,
            &stats_max,
            num_of_nodes,
            1,
        );
    }

    fn print_metric(
        nodes_missed: f64,
        msgs_missed: f64,
        stats: &Statistics,
        num_of_nodes: u32,
        num_of_msgs: u32,
    ) {
        println!(
            "rounds: {}, empty_pulls: {}, empty_pushes: {}, full_msgs_sent: {}, msgs_missed: {} \
             ({:.2}%), nodes_missed: {} ({:.2}%)",
            stats.rounds,
            stats.empty_pull_sent,
            stats.empty_push_sent,
            stats.full_message_sent,
            msgs_missed,
            100.0 * msgs_missed / f64::from(num_of_nodes) / f64::from(num_of_msgs),
            nodes_missed,
            100.0 * nodes_missed / f64::from(num_of_nodes) / f64::from(num_of_msgs)
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
                print!(
                    "Network of {} nodes, gossiping {} messages:\n\t",
                    nodes, msgs
                );
                let mut gossipers = create_network(*nodes);
                let metric = send_messages(&mut gossipers, *msgs);
                print_metric(metric.0 as f64, metric.1 as f64, &metric.2, *nodes, *msgs);
            }
        }
    }
}
