// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::id::Id;
use crate::messages::GossipType;
use crate::rumor_state::RumorState;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::{cmp, mem, u64};

/// Gossip protocol handler.
pub struct Gossip {
    rumors: BTreeMap<Vec<u8>, RumorState>,
    network_size: f64,
    // When in state B, if our age for a Rumor is incremented to this value, the state
    // transitions to C.  Specified in the paper as `O(ln ln n)`.
    max_b_age: u8,
    // The maximum number of rounds to remain in state C for a given rumor.  Specified in the
    // paper as `O(ln ln n)`.
    max_c_rounds: u8,
    // The maximum total number of rounds for a rumor to remain in states B or C.  This is a
    // failsafe to allow the definite termination of a rumor being propagated.  Specified in the
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
            rumors: BTreeMap::new(),
            network_size: 1.0,
            max_b_age: 0,
            max_c_rounds: 0,
            max_rounds: 0,
            peers_in_this_round: BTreeSet::new(),
            statistics: Statistics::default(),
        }
    }

    pub fn add_peer(&mut self) {
        self.network_size += 1.0;
        self.max_b_age = cmp::max(1, self.network_size.ln().ln().ceil() as u8);
        self.max_c_rounds = cmp::max(1, self.network_size.ln().ln().ceil() as u8);
        self.max_rounds = cmp::max(1, self.network_size.ln().ceil() as u8);
    }

    pub fn rumors(&self) -> Vec<Vec<u8>> {
        self.rumors.keys().cloned().collect()
    }

    /// Start gossiping a new rumor from this node.
    pub fn initiate_rumor(&mut self, msg: Vec<u8>) {
        if self.rumors.insert(msg, RumorState::new()).is_some() {
            error!("New rumors should be unique.");
        }
    }

    /// Trigger the end of this round.  Returns a list of Push requests to be sent to a single random
    /// peer during this new round.
    pub fn next_round(&mut self) -> Vec<GossipType> {
        self.statistics.rounds += 1;
        let mut push_list = vec![];
        let rumors = mem::replace(&mut self.rumors, BTreeMap::new());
        self.rumors = rumors
            .into_iter()
            .map(|(rumor, state)| {
                let new_state = state.next_round(
                    self.max_b_age,
                    self.max_c_rounds,
                    self.max_rounds,
                    &self.peers_in_this_round,
                );
                // Filter out any for which `our_age()` is `None`.
                if let Some(age) = new_state.our_age() {
                    push_list.push(GossipType::Push {
                        msg: rumor.clone(),
                        age,
                    });
                }
                (rumor, new_state)
            })
            .collect();
        self.peers_in_this_round.clear();
        self.statistics.sent_rumors += push_list.len() as u64;
        push_list
    }

    /// We've received `request` from `peer_id`.  If this is a Push request and we've not already heard from
    /// `peer_id` in this round, this returns the list of Pull requests which should be sent back to
    /// `peer_id`.
    pub fn receive(&mut self, peer_id: Id, request: GossipType) -> Vec<GossipType> {
        let (is_push, rumor, age) = match request {
            GossipType::Push { msg, age } => (true, msg, age),
            GossipType::Pull { msg, age } => (false, msg, age),
        };

        // Collect any responses required.
        let is_new_this_round = self.peers_in_this_round.insert(peer_id);
        let responses = if is_new_this_round && is_push {
            let responses: Vec<GossipType> = self
                .rumors
                .iter()
                .filter_map(|(rumor, state)| {
                    // Filter out any for which `our_age()` is `None`.
                    state.our_age().map(|age| GossipType::Pull {
                        msg: rumor.clone(),
                        age,
                    })
                })
                .collect();
            self.statistics.sent_rumors += responses.len() as u64;
            responses
        } else {
            vec![]
        };

        // Empty Push & Pull shall not be inserted into cache.
        if !(rumor.is_empty() && age == 0) {
            self.statistics.received_rumors += 1;
            // Add or update the entry for this rumor.
            match self.rumors.entry(rumor) {
                Entry::Occupied(mut entry) => entry.get_mut().receive(peer_id, age),
                Entry::Vacant(entry) => {
                    let _ = entry.insert(RumorState::new_from_peer(age, self.max_b_age));
                }
            }
        }

        responses
    }

    #[cfg(test)]
    /// Clear the cache.
    pub fn clear(&mut self) {
        self.statistics = Statistics::default();
        self.rumors.clear();
        self.peers_in_this_round.clear();
    }

    /// Returns the statistics.
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
}

impl Debug for Gossip {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "Gossip {{ rumors: {{ ")?;
        for (rumor, state) in &self.rumors {
            write!(
                formatter,
                "{:02x}{:02x}{:02x}{:02x}: {:?}, ",
                rumor[0], rumor[1], rumor[2], rumor[3], state
            )?;
        }
        write!(formatter, "}}, network_size: {}, ", self.network_size)?;
        write!(formatter, "max_b_age: {}, ", self.max_b_age)?;
        write!(formatter, "max_c_rounds: {}, ", self.max_c_rounds)?;
        write!(formatter, "max_rounds: {}, ", self.max_rounds)?;
        write!(
            formatter,
            "peers_in_this_round: {:?} }}",
            self.peers_in_this_round
        )
    }
}

/// Statistics on each node.
#[derive(Clone, Copy, Default)]
pub struct Statistics {
    /// Total rounds experienced (each push_tick is considered as one round).
    pub rounds: u64,
    /// Total rumors sent from this node.
    pub sent_rumors: u64,
    /// Total rumors this node received.
    pub received_rumors: u64,
}

impl Statistics {
    /// Create a default with u64::MAX
    pub fn new_max() -> Self {
        Statistics {
            rounds: u64::MAX,
            sent_rumors: u64::MAX,
            received_rumors: u64::MAX,
        }
    }

    /// Add the value of other into self
    pub fn add(&mut self, other: &Statistics) {
        self.rounds += other.rounds;
        self.sent_rumors += other.sent_rumors;
        self.received_rumors += other.received_rumors;
    }

    /// Update self with the min of self and other
    pub fn min(&mut self, other: &Statistics) {
        self.rounds = cmp::min(self.rounds, other.rounds);
        self.sent_rumors = cmp::min(self.sent_rumors, other.sent_rumors);
        self.received_rumors = cmp::min(self.received_rumors, other.received_rumors);
    }

    /// Update self with the max of self and other
    pub fn max(&mut self, other: &Statistics) {
        self.rounds = cmp::max(self.rounds, other.rounds);
        self.sent_rumors = cmp::max(self.sent_rumors, other.sent_rumors);
        self.received_rumors = cmp::max(self.received_rumors, other.received_rumors);
    }
}

impl Debug for Statistics {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "rounds: {}, rumors sent: {},  \n
            rumors received: {}",
            self.rounds, self.sent_rumors, self.received_rumors
        )
    }
}
