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
use super::messages::Message;
use ed25519_dalek::Keypair;
use error::Error;
use id::Id;
use maidsafe_utilities::serialisation::{self, SerialisationError};
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
}

// Push & Pull procedure is defined as:
//      * Node A randomly picks a node B and sends hot_messages and a pull request to B.
//      * When B received the pull request, it sends back its hot_messages + cold_messages
// hot_message is definded as `message_counter <= ln(N)`
// cold_message is defined as `ln(N) < message_counter <= 2ln(N)`
// message_counter only get increased when during each round: the number of copies whose
// message_counter is greater than ours, is more than those less than ours.
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
    pub fn send_new<T: Serialize>(&mut self, message: &T) -> Result<(), Error> {
        if self.peers.is_empty() {
            return Err(Error::NoPeers);
        }
        self.gossip.inform(serialisation::serialise(message)?);
        Ok(())
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

        // println!("{:?} Sending messages and pull to {:?}", self, peer_id);
        Ok((peer_id, messages))
    }

    /// Start a pull round.
    pub fn pull_tick(&self) -> Result<Vec<u8>, SerialisationError> {
        serialisation::serialise(&Message::Pull)
    }

    /// Handles an incoming message from peer.
    pub fn handle_received_message(&mut self, _peer_id: &Id, message: &[u8]) -> Vec<Vec<u8>> {
        // println!(
        //     "{:?} handling message of {} bytes from {:?}",
        //     self,
        //     message.len(),
        //     peer_id
        // );
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
                    // println!("{:?} Sending message: {:?} to {:?}", self, msg, peer_id);
                    if let Ok(str) = serialisation::serialise(&Message::Push(count, msg)) {
                        response.push(str);
                    }
                }
            }
        }
        response
    }

    #[cfg(test)]
    pub fn get_messages(&self) -> Vec<Vec<u8>> {
        self.gossip.get_messages()
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
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Metrics {
        rounds: u64,
        total_pulls: u64,
        total_pushes: u64,
        total_pull_respones: u64,
        total_full_message: u64,
        msg_missed: u64,
        nodes_missed: u64,
    }

    impl Metrics {
        fn new_max() -> Self {
            Metrics {
                rounds: u64::MAX,
                total_pulls: u64::MAX,
                total_pushes: u64::MAX,
                total_pull_respones: u64::MAX,
                total_full_message: u64::MAX,
                msg_missed: u64::MAX,
                nodes_missed: u64::MAX,
            }
        }

        fn add(&mut self, other: &Metrics) {
            self.rounds += other.rounds;
            self.total_pulls += other.total_pulls;
            self.total_pushes += other.total_pushes;
            self.total_pull_respones += other.total_pull_respones;
            self.total_full_message += other.total_full_message;
            self.msg_missed += other.msg_missed;
            self.nodes_missed += other.nodes_missed;
        }

        fn min(&mut self, other: &Metrics) {
            self.rounds = cmp::min(self.rounds, other.rounds);
            self.total_pulls = cmp::min(self.total_pulls, other.total_pulls);
            self.total_pushes = cmp::min(self.total_pushes, other.total_pushes);
            self.total_pull_respones =
                cmp::min(self.total_pull_respones, other.total_pull_respones);
            self.total_full_message = cmp::min(self.total_full_message, other.total_full_message);
            self.msg_missed = cmp::min(self.msg_missed, other.msg_missed);
            self.nodes_missed = cmp::min(self.nodes_missed, other.nodes_missed);
        }

        fn max(&mut self, other: &Metrics) {
            self.rounds = cmp::max(self.rounds, other.rounds);
            self.total_pulls = cmp::max(self.total_pulls, other.total_pulls);
            self.total_pushes = cmp::max(self.total_pushes, other.total_pushes);
            self.total_pull_respones =
                cmp::max(self.total_pull_respones, other.total_pull_respones);
            self.total_full_message = cmp::max(self.total_full_message, other.total_full_message);
            self.msg_missed = cmp::max(self.msg_missed, other.msg_missed);
            self.nodes_missed = cmp::max(self.nodes_missed, other.nodes_missed);
        }
    }

    impl Debug for Metrics {
        fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
            writeln!(
                formatter,
                "rounds: {} total_pulls {} total_pushes {} total_pull_respones {} \
             total_full_message {} msg_missed {} nodes_missed {}",
                self.rounds,
                self.total_pulls,
                self.total_pushes,
                self.total_pull_respones,
                self.total_full_message,
                self.msg_missed,
                self.nodes_missed
            )
        }
    }

    #[test]
    fn one_message() {
        let iterations = 1000;
        let mut metrics = Vec::new();
        for _ in 0..iterations {
            metrics.push(send_one_message_and_gossip())
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
            "AVERAGE -- rounds: {} total_pulls {} total_pushes {} total_pull_respones {} \
             total_full_message {} msg_missed {} nodes_missed {}",
            metrics_total.rounds / iterations,
            metrics_total.total_pulls / iterations,
            metrics_total.total_pushes / iterations,
            metrics_total.total_pull_respones / iterations,
            metrics_total.total_full_message / iterations,
            metrics_total.msg_missed as f64 / iterations as f64,
            metrics_total.nodes_missed as f64 / iterations as f64
        );
        println!("MIN -- {:?}", metrics_min);
        println!("MAX -- {:?}", metrics_max);
    }

    fn send_one_message_and_gossip() -> Metrics {
        let node_count = 16;
        let mut gossipers = itertools::repeat_call(Gossiper::default)
            .take(node_count)
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
        // Inform one message.
        {
            let gossiper = unwrap!(rand::thread_rng().choose_mut(&mut gossipers));
            let _ = gossiper.send_new(&"hello".to_string());
        }

        let mut metrics = Metrics::default();

        // Polling
        let mut processed = true;
        while processed {
            processed = false;
            metrics.rounds += 1;
            let mut messages = BTreeMap::new();
            for gossiper in gossipers.iter_mut() {
                let (dst, msgs) = unwrap!(gossiper.push_tick());
                if msgs.len() > 1 {
                    metrics.total_pushes += msgs.len() as u64 - 1;
                    metrics.total_full_message += msgs.len() as u64 - 1;
                    processed = true;
                }
                let _ = messages.insert((gossiper.id(), dst), msgs);
            }
            metrics.total_pulls += node_count as u64;
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
                    metrics.total_pull_respones += result.len() as u64;
                    metrics.total_full_message += result.len() as u64;
                    let _ = responses.insert((dst, src), result);
                    // println!("responses {:?}", responses);
                }
                messages = responses;
                // println!("messages {:?}", messages);
            }
        }

        // Checking nodes missed the message
        for gossiper in &gossipers {
            if gossiper.get_messages().is_empty() {
                metrics.nodes_missed += 1;
                metrics.msg_missed = 1;
            }
            // println!("{:?} has {:?}", gossiper.id(), gossiper.get_messages());
        }
        metrics
    }

    #[test]
    fn multiple_messages() {
        let node_count = 16;
        let msg_count = 1000;
        let mut rng = SeededRng::thread_rng();

        let mut gossipers = itertools::repeat_call(Gossiper::default)
            .take(node_count)
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

        let mut rumors: Vec<String> = Vec::new();
        for _ in 0..msg_count {
            let raw: Vec<u8> = rng.gen_iter().take(20).collect();
            rumors.push(String::from_utf8_lossy(&raw).to_string());
        }

        let mut metrics = Metrics::default();

        // Polling
        let mut processed = true;
        while processed {
            processed = false;
            metrics.rounds += 1;
            let mut messages = BTreeMap::new();
            for gossiper in gossipers.iter_mut() {
                if rng.gen() && !rumors.is_empty() {
                    let rumor = unwrap!(rumors.pop());
                    let _ = gossiper.send_new(&rumor);
                }
                let (dst, msgs) = unwrap!(gossiper.push_tick());
                if msgs.len() > 1 {
                    metrics.total_pushes += msgs.len() as u64 - 1;
                    metrics.total_full_message += msgs.len() as u64 - 1;
                    processed = true;
                }
                let _ = messages.insert((gossiper.id(), dst), msgs);
            }
            metrics.total_pulls += node_count as u64;
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
                    metrics.total_pull_respones += result.len() as u64;
                    metrics.total_full_message += result.len() as u64;
                    let _ = responses.insert((dst, src), result);
                    // println!("responses {:?}", responses);
                }
                messages = responses;
                // println!("messages {:?}", messages);
            }
        }

        // Checking nodes missed the message
        let mut max_missed_msg_on_one_node = 0;
        let mut min_missed_msg_on_one_node = u64::MAX;
        for gossiper in &gossipers {
            if gossiper.get_messages().len() != msg_count {
                metrics.nodes_missed += 1;
                let missed_msgs = (msg_count - gossiper.get_messages().len()) as u64;
                min_missed_msg_on_one_node = cmp::min(min_missed_msg_on_one_node, missed_msgs);
                max_missed_msg_on_one_node = cmp::max(max_missed_msg_on_one_node, missed_msgs);
                metrics.msg_missed += missed_msgs;
            }
            // println!("{:?} has {:?}", gossiper.id(), gossiper.get_messages());
        }

        println!(
            "rounds: {} total_pulls {} total_pushes {} total_pull_respones {} \
             total_full_message {} msg_missed {} nodes_missed {} \
             min_missed_msg_on_one_node {}  max_missed_msg_on_one_node {}",
            metrics.rounds,
            metrics.total_pulls,
            metrics.total_pushes,
            metrics.total_pull_respones,
            metrics.total_full_message,
            metrics.msg_missed,
            metrics.nodes_missed,
            min_missed_msg_on_one_node,
            max_missed_msg_on_one_node
        );
    }
}
