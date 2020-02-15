// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::id::Id;
use crate::message_state::MessageState;
use crate::messages::GossipRpc;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::{cmp, mem, u64};

/// Gossip protocol handler.
pub struct Gossip {
    messages: BTreeMap<Vec<u8>, MessageState>,
    network_size: f64,
    // When in state B, if our counter for a message is incremented to this value, the state
    // transitions to C.  Specified in the paper as `O(ln ln n)`.
    counter_max: u8,
    // The maximum number of rounds to remain in state C for a given message.  Specified in the
    // paper as `O(ln ln n)`.
    max_c_rounds: u8,
    // The maximum total number of rounds for a message to remain in states B or C.  This is a
    // failsafe to allow the definite termination of a message being propagated.  Specified in the
    // paper as `O(ln n)`.
    max_rounds: u8,
    // All peers with which we communicated during this round.
    peers_in_this_round: BTreeSet<Id>,
    // Statistics
    statistics: Statistics,
}

impl Gossip {
    pub fn new() -> Self {
        Gossip {
            messages: BTreeMap::new(),
            network_size: 1.0,
            counter_max: 0,
            max_c_rounds: 0,
            max_rounds: 0,
            peers_in_this_round: BTreeSet::new(),
            statistics: Statistics::default(),
        }
    }

    pub fn add_peer(&mut self) {
        self.network_size += 1.0;
        self.counter_max = cmp::max(1, self.network_size.ln().ln().ceil() as u8);
        self.max_c_rounds = cmp::max(1, self.network_size.ln().ln().ceil() as u8);
        self.max_rounds = cmp::max(1, self.network_size.ln().ceil() as u8);
    }

    pub fn messages(&self) -> Vec<Vec<u8>> {
        self.messages.keys().cloned().collect()
    }

    /// Start gossiping a new message from this node.
    pub fn new_message(&mut self, msg: Vec<u8>) {
        if self.messages.insert(msg, MessageState::new()).is_some() {
            error!("New messages should be unique.");
        }
    }

    /// Trigger the end of this round.  Returns a list of Push RPCs to be sent to a single random
    /// peer during this new round.
    pub fn next_round(&mut self) -> Vec<GossipRpc> {
        self.statistics.rounds += 1;
        let mut push_list = vec![];
        let messages = mem::replace(&mut self.messages, BTreeMap::new());
        self.messages = messages
            .into_iter()
            .map(|(message, state)| {
                let new_state = state.next_round(
                    self.counter_max,
                    self.max_c_rounds,
                    self.max_rounds,
                    &self.peers_in_this_round,
                );
                // Filter out any for which `our_counter()` is `None`.
                if let Some(counter) = new_state.our_counter() {
                    push_list.push(GossipRpc::Push {
                        msg: message.clone(),
                        counter,
                    });
                }
                (message, new_state)
            })
            .collect();
        self.peers_in_this_round.clear();
        self.statistics.full_message_sent += push_list.len() as u64;
        // Sends an empty Push in case of nothing to push. It acts as a fetch request to peer.
        if push_list.is_empty() {
            self.statistics.empty_push_sent += 1;
            push_list.push(GossipRpc::Push {
                msg: Vec::new(),
                counter: 0,
            });
        }
        push_list
    }

    /// We've received `rpc` from `peer_id`.  If this is a Push RPC and we've not already heard from
    /// `peer_id` in this round, this returns the list of Pull RPCs which should be sent back to
    /// `peer_id`.
    pub fn receive(&mut self, peer_id: Id, rpc: GossipRpc) -> Vec<GossipRpc> {
        let (is_push, message, counter) = match rpc {
            GossipRpc::Push { msg, counter } => (true, msg, counter),
            GossipRpc::Pull { msg, counter } => (false, msg, counter),
        };

        // Collect any responses required.
        let is_new_this_round = self.peers_in_this_round.insert(peer_id);
        let responses = if is_new_this_round && is_push {
            let mut responses: Vec<GossipRpc> = self
                .messages
                .iter()
                .filter_map(|(message, state)| {
                    // Filter out any for which `our_counter()` is `None`.
                    state.our_counter().map(|counter| GossipRpc::Pull {
                        msg: message.clone(),
                        counter,
                    })
                })
                .collect();
            self.statistics.full_message_sent += responses.len() as u64;
            // Empty Pull notifies the peer that all messages in this node was in State A.
            if responses.is_empty() {
                self.statistics.empty_pull_sent += 1;
                responses.push(GossipRpc::Pull {
                    msg: Vec::new(),
                    counter: 0,
                });
            }
            responses
        } else {
            vec![]
        };

        // Empty Push & Pull shall not be inserted into cache.
        if !(message.is_empty() && counter == 0) {
            self.statistics.full_message_received += 1;
            // Add or update the entry for this message.
            match self.messages.entry(message) {
                Entry::Occupied(mut entry) => entry.get_mut().receive(peer_id, counter),
                Entry::Vacant(entry) => {
                    let _ = entry.insert(MessageState::new_from_peer(counter, self.counter_max));
                }
            }
        }

        responses
    }

    #[cfg(test)]
    /// Clear the cache.
    pub fn clear(&mut self) {
        self.statistics = Statistics::default();
        self.messages.clear();
        self.peers_in_this_round.clear();
    }

    /// Returns the statistics.
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
}

impl Debug for Gossip {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "Gossip {{ messages: {{ ")?;
        for (message, state) in &self.messages {
            write!(
                formatter,
                "{:02x}{:02x}{:02x}{:02x}: {:?}, ",
                message[0], message[1], message[2], message[3], state
            )?;
        }
        write!(formatter, "}}, network_size: {}, ", self.network_size)?;
        write!(formatter, "counter_max: {}, ", self.counter_max)?;
        write!(formatter, "max_c_rounds: {}, ", self.max_c_rounds)?;
        write!(formatter, "max_rounds: {}, ", self.max_rounds)?;
        write!(
            formatter,
            "peers_in_this_round: {:?} }}",
            self.peers_in_this_round
        )
    }
}

/// Statistics on each gossiper.
#[derive(Clone, Copy, Default)]
pub struct Statistics {
    /// Total rounds experienced (each push_tick is considered as one round).
    pub rounds: u64,
    /// Total empty pull sent from this gossiper.
    pub empty_pull_sent: u64,
    /// Total empty push sent from this gossiper.
    pub empty_push_sent: u64,
    /// Total full message sent from this gossiper.
    pub full_message_sent: u64,
    /// Total full message this gossiper received.
    pub full_message_received: u64,
}

impl Statistics {
    /// Create a default with u64::MAX
    pub fn new_max() -> Self {
        Statistics {
            rounds: u64::MAX,
            empty_pull_sent: u64::MAX,
            empty_push_sent: u64::MAX,
            full_message_sent: u64::MAX,
            full_message_received: u64::MAX,
        }
    }

    /// Add the value of other into self
    pub fn add(&mut self, other: &Statistics) {
        self.rounds += other.rounds;
        self.empty_pull_sent += other.empty_pull_sent;
        self.empty_push_sent += other.empty_push_sent;
        self.full_message_sent += other.full_message_sent;
        self.full_message_received += other.full_message_received;
    }

    /// Update self with the min of self and other
    pub fn min(&mut self, other: &Statistics) {
        self.rounds = cmp::min(self.rounds, other.rounds);
        self.empty_pull_sent = cmp::min(self.empty_pull_sent, other.empty_pull_sent);
        self.empty_push_sent = cmp::min(self.empty_push_sent, other.empty_push_sent);
        self.full_message_sent = cmp::min(self.full_message_sent, other.full_message_sent);
        self.full_message_received =
            cmp::min(self.full_message_received, other.full_message_received);
    }

    /// Update self with the max of self and other
    pub fn max(&mut self, other: &Statistics) {
        self.rounds = cmp::max(self.rounds, other.rounds);
        self.empty_pull_sent = cmp::max(self.empty_pull_sent, other.empty_pull_sent);
        self.empty_push_sent = cmp::max(self.empty_push_sent, other.empty_push_sent);
        self.full_message_sent = cmp::max(self.full_message_sent, other.full_message_sent);
        self.full_message_received =
            cmp::max(self.full_message_received, other.full_message_received);
    }
}

impl Debug for Statistics {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "rounds: {},  empty pull sent: {},  empty push sent: {}, full messages sent: {},  \n
             full messages received: {}",
            self.rounds,
            self.empty_pull_sent,
            self.empty_push_sent,
            self.full_message_sent,
            self.full_message_received
        )
    }
}
