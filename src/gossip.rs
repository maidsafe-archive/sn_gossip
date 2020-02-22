// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::id::Id;
use crate::messages::Gossip;
use crate::rumor_state::RumorState;
use crate::rumor_state::{Age, Round};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::{cmp, mem, u64};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Content(pub Vec<u8>);

#[derive(Debug, Ord, Eq, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub struct ContentHash(pub Vec<u8>);
impl ContentHash {
    fn from(content: Content) -> Self {
        // todo
        Self(content.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rumor {
    pub content: Content,
    pub state: RumorState,
}

/// The gossip state of a node instance.
pub struct GossipState {
    rumors: BTreeMap<ContentHash, Rumor>,
    network_size: f64,
    // When in state B, if our age for a Rumor is incremented to this value, the state
    // transitions to C.  Specified in the paper as `O(ln ln n)`.
    max_b_age: Age,
    // The maximum number of rounds to remain in state C for a given rumor.  Specified in the
    // paper as `O(ln ln n)`.
    max_c_rounds: Round,
    // The maximum total number of rounds for a rumor to remain in states B or C.  This is a
    // failsafe to allow the definite termination of a rumor being propagated.  Specified in the
    // paper as `O(ln n)`.
    max_rounds: Round,
    // All peers with which we communicated during this round.
    peers_in_this_round: BTreeSet<Id>,
    // Statistics
    statistics: Statistics,
}

impl GossipState {
    pub fn new() -> Self {
        GossipState {
            rumors: BTreeMap::new(),
            network_size: 1.0,
            max_b_age: Age::from(0),
            max_c_rounds: Round::from(0),
            max_rounds: Round::from(0),
            peers_in_this_round: BTreeSet::new(),
            statistics: Statistics::default(),
        }
    }

    pub fn add_peer(&mut self) {
        self.network_size += 1.0;
        self.max_b_age = Age::from(cmp::max(1, self.network_size.ln().ln().ceil() as u8));
        self.max_c_rounds = Round::from(cmp::max(1, self.network_size.ln().ln().ceil() as u8));
        self.max_rounds = Round::from(cmp::max(1, self.network_size.ln().ceil() as u8));
    }

    pub fn rumors(&self) -> Vec<Rumor> {
        self.rumors.values().cloned().collect()
    }

    /// Start gossiping a new rumor from this node.
    pub fn initiate_rumor(&mut self, content: Content) {
        if self
            .rumors
            .insert(
                ContentHash::from(content.clone()),
                Rumor {
                    content,
                    state: RumorState::new(),
                },
            )
            .is_some()
        {
            error!("New rumors should be unique.");
        }
    }

    /// Trigger the end of this round.  Returns a list of Push gossips to be sent to a single random
    /// peer during this new round.
    pub fn next_round(&mut self) -> Option<Gossip> {
        self.statistics.rounds += 1;
        let mut rumors_to_push = vec![];
        let rumors = mem::replace(&mut self.rumors, BTreeMap::new());
        self.rumors = rumors
            .into_iter()
            .map(|(hash, mut rumor)| {
                rumor.state = rumor.state.next_round(
                    self.max_b_age,
                    self.max_c_rounds,
                    self.max_rounds,
                    &self.peers_in_this_round,
                );
                // Filter out any for which `rumor_age()` is `None`.
                if rumor.state.rumor_age().is_some() {
                    rumors_to_push.push(rumor.clone());
                }
                (hash, rumor)
            })
            .collect();
        self.peers_in_this_round.clear();
        self.statistics.sent_rumors += rumors_to_push.len() as u64;
        if !rumors_to_push.is_empty() {
            Some(Gossip::Push(rumors_to_push))
        } else {
            None
        }
    }

    /// We've received `gossip` from `peer_id`.  If this is a Push gossip and we've not already heard from
    /// `peer_id` in this round, this returns the list of Pull gossips which should be sent back to
    /// `peer_id`.
    pub fn receive(&mut self, peer_id: Id, gossip: Gossip) -> Option<Gossip> {
        let (is_push, received_rumors) = match gossip {
            Gossip::Push(received_rumors) => (true, received_rumors),
            Gossip::Pull(received_rumors) => (false, received_rumors),
        };

        // Collect any responses required.
        let is_new_this_round = self.peers_in_this_round.insert(peer_id);
        let response = if is_new_this_round && is_push {
            let response_rumors: Vec<Rumor> = self
                .rumors
                .iter()
                .filter_map(|(_, rumor)| {
                    // Filter out any for which `rumor_age()` is `None`.
                    rumor.state.rumor_age().map(|_| rumor.clone())
                })
                .collect();
            self.statistics.sent_rumors += response_rumors.len() as u64;
            let response_gossip = Gossip::Pull(response_rumors);
            Some(response_gossip)
        } else {
            None
        };

        for rumor in received_rumors {
            self.statistics.received_rumors += 1;
            // Add or update the entry for this rumor.
            let age = rumor.state.rumor_age().unwrap_or_else(Age::max);
            match self.rumors.entry(ContentHash::from(rumor.content.clone())) {
                Entry::Occupied(mut entry) => entry.get_mut().state.receive(peer_id, age),
                Entry::Vacant(entry) => {
                    let _ = entry.insert(Rumor {
                        content: rumor.content,
                        state: RumorState::new_from_peer(age, self.max_b_age),
                    });
                }
            }
        }

        response
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

impl Debug for GossipState {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "GossipState {{ rumors: {{ ")?;
        for rumor in (&self.rumors).values() {
            write!(
                formatter,
                "{:02x}{:02x}{:02x}{:02x}: {:?}, ",
                rumor.content.0[0],
                rumor.content.0[1],
                rumor.content.0[2],
                rumor.content.0[3],
                rumor.state
            )?;
        }
        write!(formatter, "}}, network_size: {}, ", self.network_size)?;
        write!(formatter, "max_b_age: {}, ", self.max_b_age.value)?;
        write!(formatter, "max_c_rounds: {}, ", self.max_c_rounds.value)?;
        write!(formatter, "max_rounds: {}, ", self.max_rounds.value)?;
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
