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

/// An entity on the network which will gossip rumors.
pub struct Node {
    keys: Keypair,
    peers: Vec<Id>,
    gossip: Gossip,
}

impl Node {
    /// The ID of this `Node`, i.e. its public key.
    pub fn id(&self) -> Id {
        self.keys.public.into()
    }

    /// Add the ID of another node on the network.  This will fail if `initiate_rumor()` has already been
    /// called since this `Node` needs to know about all other nodes in the network before
    /// starting to gossip rumors.
    pub fn add_peer(&mut self, peer_id: Id) -> Result<(), Error> {
        if !self.gossip.rumors().is_empty() {
            return Err(Error::AlreadyStarted);
        }
        self.peers.push(peer_id);
        self.gossip.add_peer();
        Ok(())
    }

    /// Initiate a new rumor starting at this `Node`.
    pub fn initiate_rumor<T: Serialize>(&mut self, rumor: &T) -> Result<(), Error> {
        if self.peers.is_empty() {
            return Err(Error::NoPeers);
        }
        self.gossip.initiate_rumor(serialize(rumor)?);
        Ok(())
    }

    /// Start a new round.  Returns a vector of Push requests with rumors to be sent to the given peer.
    ///
    /// These should all be given to just a single peer to avoid triggering a flood of Pull requests in
    /// response.  For example, if we have 100 Push requests to send here and we send them all to a
    /// single peer, we only receive a single tranche of Pull requests in responses (the tranche
    /// comprising several rumors).  However, if we send each Push request to a different peer, we'd
    /// receive 100 tranches of Pull requests.
    pub fn next_round(&mut self) -> Result<(Id, Vec<Vec<u8>>), Error> {
        let mut rng = rand::thread_rng();
        let peer_id = match self.peers.choose(&mut rng) {
            Some(id) => *id,
            None => return Err(Error::NoPeers),
        };
        let push_list = self.gossip.next_round();
        let rumors = self.prepare_to_send(push_list);
        debug!("{:?} Sending Push rumors to {:?}", self, peer_id);
        Ok((peer_id, rumors))
    }

    /// Handles an incoming rumor from peer.
    pub fn receive_rumor(&mut self, peer_id: &Id, serialised_rumor: &[u8]) -> Vec<Vec<u8>> {
        debug!("{:?} handling rumor from {:?}", self, peer_id);
        let pub_key = if let Ok(pub_key) = PublicKey::from_bytes(&peer_id.0) {
            pub_key
        } else {
            return Vec::new();
        };
        let request = if let Ok(request) = Message::deserialise(serialised_rumor, &pub_key) {
            request
        } else {
            error!("Failed to deserialise rumor");
            return Vec::new();
        };
        // If this request is a Push from a peer we've not already heard from in this round, there could
        // be a set of Pull responses to be sent back to that peer.
        let responses = self.gossip.receive(*peer_id, request);
        self.prepare_to_send(responses)
    }

    /// Returns the list of rumors this node is informed about so far.
    pub fn rumors(&self) -> Vec<Vec<u8>> {
        self.gossip.rumors()
    }

    /// Returns the statistics of this node.
    pub fn statistics(&self) -> Statistics {
        self.gossip.statistics()
    }

    #[cfg(test)]
    /// Clear the statistics and gossip's cache.
    pub fn clear(&mut self) {
        self.gossip.clear();
    }

    fn prepare_to_send(&mut self, requests: Vec<GossipType>) -> Vec<Vec<u8>> {
        let mut rumors = vec![];
        for request in requests {
            if let Ok(serialised_msg) = Message::serialise(&request, &self.keys) {
                rumors.push(serialised_msg);
            } else {
                error!("Failed to serialise {:?}", request);
            }
        }
        rumors
    }
}

impl Default for Node {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let keys = Keypair::generate::<Sha3_512, _>(&mut rng);
        Node {
            keys,
            peers: vec![],
            gossip: Gossip::new(),
        }
    }
}

impl Debug for Node {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rumor_state::Age;
    use itertools::Itertools;
    use rand::seq::SliceRandom;
    use rand::{self, Rng};
    use std::collections::BTreeMap;
    use std::time::Instant;
    use std::{cmp, u64};

    fn create_network(node_count: u32) -> Vec<Node> {
        let mut nodes = std::iter::repeat_with(Node::default)
            .take(node_count as usize)
            .collect_vec();
        // Connect all the nodes.
        for i in 0..(nodes.len() - 1) {
            let lhs_id = nodes[i].id();
            for j in (i + 1)..nodes.len() {
                let rhs_id = nodes[j].id();
                let _ = nodes[j].add_peer(lhs_id);
                let _ = nodes[i].add_peer(rhs_id);
            }
        }
        nodes
    }

    fn send_rumors(nodes: &mut Vec<Node>, num_of_msgs: u32) -> (u64, u64, Statistics) {
        let mut rng = rand::thread_rng();
        let empty_request_len = unwrap!(Message::serialise(
            &GossipType::Push {
                msg: vec![],
                age: Age::from(0),
            },
            &nodes[0].keys,
        ))
        .len();

        let mut rumors: Vec<String> = Vec::new();
        for _ in 0..num_of_msgs {
            let mut raw = [0u8; 20];
            rng.fill(&mut raw[..]);
            rumors.push(String::from_utf8_lossy(&raw).to_string());
        }

        // Initiate the first rumor.
        {
            assert!(num_of_msgs >= 1);
            let node = unwrap!(nodes.choose_mut(&mut rng));
            let rumor = unwrap!(rumors.pop());
            let _ = node.initiate_rumor(&rumor);
        }

        // Polling
        let mut processed = true;
        while processed {
            processed = false;
            let mut to_push = BTreeMap::new();
            // Call `next_round()` on each node to gather a list of all Push requests.
            for node in nodes.iter_mut() {
                if !rumors.is_empty() && rng.gen() {
                    let rumor = unwrap!(rumors.pop());
                    let _ = node.initiate_rumor(&rumor);
                }
                let (dst_id, push_msgs) = unwrap!(node.next_round());
                // Any non-empty Push request will have a length more than `empty_request_len`.
                if push_msgs.iter().any(|msg| msg.len() > empty_request_len) {
                    processed = true;
                }
                let _ = to_push.insert((node.id(), dst_id), push_msgs);
            }

            // Send all Push requests and the corresponding Pull requests.
            for ((src_id, dst_id), push_msgs) in to_push {
                let mut pull_msgs = vec![];
                {
                    let dst = unwrap!(nodes.iter_mut().find(|node| node.id() == dst_id));
                    // Only the first Push from this peer should return any Pulls.
                    for (index, push_msg) in push_msgs.into_iter().enumerate() {
                        if index == 0 {
                            pull_msgs = dst.receive_rumor(&src_id, &push_msg);
                        } else {
                            assert!(dst.receive_rumor(&src_id, &push_msg).is_empty());
                        }
                    }
                }
                let src = unwrap!(nodes.iter_mut().find(|node| node.id() == src_id));
                for pull_msg in pull_msgs {
                    assert!(src.receive_rumor(&dst_id, &pull_msg).is_empty());
                }
            }
        }

        let mut statistics = Statistics::default();
        let mut nodes_missed = 0;
        let mut msgs_missed = 0;
        // Checking nodes missed the rumor, and clear the nodes for the next iteration.
        for node in nodes.iter_mut() {
            let stat = node.statistics();
            statistics.add(&stat);
            statistics.rounds = stat.rounds;

            if node.rumors().len() as u32 != num_of_msgs {
                nodes_missed += 1;
                msgs_missed += u64::from(num_of_msgs - node.rumors().len() as u32);
            }
            node.clear();
        }

        (nodes_missed, msgs_missed, statistics)
    }

    fn one_rumor_test(num_of_nodes: u32) {
        let mut nodes = create_network(num_of_nodes);
        println!("Network of {} nodes:", num_of_nodes);
        let iterations = 100;
        let mut metrics = Vec::new();
        for _ in 0..iterations {
            metrics.push(send_rumors(&mut nodes, 1));
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
        stats_avg.sent_rumors /= iterations;
        stats_avg.received_rumors /= iterations;

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
            "rounds: {}, msgs_sent: {}, msgs_missed: {} \
             ({:.2}%), nodes_missed: {} ({:.2}%)",
            stats.rounds,
            stats.sent_rumors,
            msgs_missed,
            100.0 * msgs_missed / f64::from(num_of_nodes) / f64::from(num_of_msgs),
            nodes_missed,
            100.0 * nodes_missed / f64::from(num_of_nodes) / f64::from(num_of_msgs)
        );
    }

    #[test]
    fn one_rumor() {
        one_rumor_test(20);
        one_rumor_test(200);
        one_rumor_test(2000);
    }

    #[test]
    fn multiple_rumors() {
        let num_of_nodes: Vec<u32> = vec![20, 200, 2000];
        let num_of_msgs: Vec<u32> = vec![10, 100, 1000];
        for number in &num_of_nodes {
            for msgs in &num_of_msgs {
                print!(
                    "Network of {} nodes, gossiping {} rumors:\n\t",
                    number, msgs
                );
                let mut nodes = create_network(*number);
                let metric = send_rumors(&mut nodes, *msgs);
                print_metric(metric.0 as f64, metric.1 as f64, &metric.2, *number, *msgs);
            }
        }
    }

    #[test]
    fn avg_rounds_and_missed() {
        let num_nodes = 20;
        let num_msgs = 1;
        let iters = 100;
        let mut all_rounds = vec![];
        let mut all_missed = vec![];
        let mut total_rounds = 0;
        let mut total_missed = 0;
        let t = Instant::now();
        for _ in 0..iters {
            let (rounds, nodes_missed) = prove_of_stop(num_nodes, num_msgs);
            all_rounds.push(rounds);
            all_missed.push(nodes_missed);
            total_rounds += rounds;
            total_missed += nodes_missed;
        }
        println!("Elapsed time: {:?}", t.elapsed());
        all_rounds.sort();
        all_missed.sort();
        let avg_rounds = total_rounds / iters;
        let avg_missed = total_missed / iters;
        let median_rounds = all_rounds[iters / 2];
        let median_missed = all_missed[iters / 2];

        println!("Iters: {:?}", iters);
        println!("Avg rounds: {:?}", avg_rounds);
        println!("Median rounds: {:?}", median_rounds);
        println!(
            "Avg missed percent: {1:.*} %",
            2,
            100_f32 * (avg_missed as f32 / num_nodes as f32)
        );
        println!(
            "Median missed percent: {1:.*} %",
            2,
            100_f32 * (median_missed as f32 / num_nodes as f32)
        );
    }

    fn prove_of_stop(num_nodes: u32, num_msgs: u32) -> (usize, usize) {
        let mut gossipers = create_network(num_nodes);
        let mut rng = rand::thread_rng();
        let mut rumors: Vec<String> = Vec::new();
        for _ in 0..num_msgs {
            let mut raw = [0u8; 20];
            rng.fill(&mut raw[..]);
            rumors.push(String::from_utf8_lossy(&raw).to_string());
        }

        let mut rounds = 0;
        // Polling
        let mut processed = true;
        while processed {
            rounds += 1;
            processed = false;
            let mut messages = BTreeMap::new();
            // Call `next_round()` on each node to gather a list of all Push requests.
            for gossiper in gossipers.iter_mut() {
                if !rumors.is_empty() && rng.gen() {
                    let rumor = unwrap!(rumors.pop());
                    let _ = gossiper.initiate_rumor(&rumor);
                }
                let (dst_id, push_msgs) = unwrap!(gossiper.next_round());
                if !push_msgs.is_empty() {
                    processed = true;
                }
                let _ = messages.insert((gossiper.id(), dst_id), push_msgs);
            }

            // Send all Push requests and the corresponding Pull requests.
            for ((src_id, dst_id), push_msgs) in messages {
                let mut pull_msgs = vec![];
                {
                    let dst = unwrap!(gossipers.iter_mut().find(|node| node.id() == dst_id));
                    // Only the first Push from this peer should return any Pulls.
                    for (index, push_msg) in push_msgs.into_iter().enumerate() {
                        if index == 0 {
                            pull_msgs = dst.receive_rumor(&src_id, &push_msg);
                        } else {
                            assert!(dst.receive_rumor(&src_id, &push_msg).is_empty());
                        }
                    }
                }
                let src = unwrap!(gossipers.iter_mut().find(|node| node.id() == src_id));
                for pull_msg in pull_msgs {
                    assert!(src.receive_rumor(&dst_id, &pull_msg).is_empty());
                }
            }
        }

        let mut nodes_missed = 0;
        // Checking if nodes missed the rumor.
        for gossiper in gossipers.iter() {
            if gossiper.rumors().len() as u32 != num_msgs {
                nodes_missed += 1;
            }
        }

        (rounds, nodes_missed)
    }
}
