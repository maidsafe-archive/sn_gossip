// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::id::Id;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

/// This represents the state of a single rumor from this node's perspective.
#[derive(Debug)]
pub enum RumorState {
    /// Exponential-growth phase.
    B {
        /// The round number for this rumor.  This is not a globally-synchronised variable, rather
        /// it is set to 0 when we first receive a copy of this rumor and is incremented every
        /// time `next_round()` is called.
        round: u8,
        /// Our age for this rumor.  This may increase by 1 during a single round or may
        /// remain the same depending on the ages attached to incoming copies of this rumor.
        our_age: u8,
        /// The map of <peer, age>s which have sent us this rumor during this round.
        peer_ages: BTreeMap<Id, u8>,
    },
    /// Quadratic-shrinking phase.
    C {
        /// The number of rounds performed by the node while the rumor was in state B.
        rounds_in_state_b: u8,
        /// The round number for this rumor while in state C.
        round: u8,
    },
    /// Propagation complete.
    D,
}

impl RumorState {
    /// Construct a new `RumorState` where we're the initial node for the rumor.  We start in
    /// state B with `our_age` set to `1`.
    pub fn new() -> Self {
        RumorState::B {
            round: 0,
            our_age: 1,
            peer_ages: BTreeMap::new(),
        }
    }

    /// Construct a new `RumorState` where we've received the rumor from a peer.  If that peer
    /// is in state B (`age < max_b_age`) we start in state B with `our_age` set to `1`.
    /// If the peer is in state C, we start in state C too.
    pub fn new_from_peer(age: u8, max_b_age: u8) -> Self {
        if age < max_b_age {
            return RumorState::B {
                round: 0,
                our_age: 1,
                peer_ages: BTreeMap::new(),
            };
        }
        RumorState::C {
            rounds_in_state_b: 0,
            round: 0,
        }
    }

    /// Receive a copy of this rumor from `peer_id` with `age`.
    pub fn receive(&mut self, peer_id: Id, age: u8) {
        if let RumorState::B {
            ref mut peer_ages, ..
        } = *self
        {
            if peer_ages.insert(peer_id, age).is_some() {
                debug!("Received the same rumor more than once this round from a given peer");
            }
        }
    }

    /// Increment `round` value, consuming `self` and returning the new state.
    pub fn next_round(
        self,
        max_b_age: u8,
        max_c_rounds: u8,
        max_rounds: u8,
        peers_in_this_round: &BTreeSet<Id>,
    ) -> RumorState {
        match self {
            RumorState::B {
                mut round,
                mut our_age,
                mut peer_ages,
            } => {
                round += 1;
                // If we've hit the maximum permitted number of rounds, transition to state D
                if round >= max_rounds {
                    return RumorState::D;
                }

                // For any `peers_in_this_round` which aren't accounted for in `peer_ages`, add
                // a age of `0` for them to indicate they're in state A (i.e. they didn't have
                // the rumor).
                for peer in peers_in_this_round {
                    if let Entry::Vacant(entry) = peer_ages.entry(*peer) {
                        let _ = entry.insert(0);
                    }
                }

                // Apply the median rule, but if any peer's age >= `max_b_age` (i.e. that peer
                // is in state C), transition to state C.
                let mut less = 0;
                let mut greater_or_equal = 0;
                for peer_age in peer_ages.values() {
                    if *peer_age < our_age {
                        less += 1;
                    } else if *peer_age >= max_b_age {
                        return RumorState::C {
                            rounds_in_state_b: round,
                            round: 0,
                        };
                    } else {
                        greater_or_equal += 1;
                    }
                }
                if greater_or_equal > less {
                    our_age += 1;
                }

                // If our age has reached `max_b_age`, transition to state C, otherwise remain
                // in state B.
                if our_age >= max_b_age {
                    return RumorState::C {
                        rounds_in_state_b: round,
                        round: 0,
                    };
                }
                RumorState::B {
                    round,
                    our_age,
                    peer_ages: BTreeMap::new(),
                }
            }
            RumorState::C {
                rounds_in_state_b,
                mut round,
            } => {
                round += 1;
                // If we've hit the maximum permitted number of rounds, transition to state D
                if round + rounds_in_state_b >= max_rounds {
                    return RumorState::D;
                }

                // If we've hit the maximum rounds for remaining in state C, transition to state D.
                if round >= max_c_rounds {
                    return RumorState::D;
                }

                // Otherwise remain in state C.
                RumorState::C {
                    rounds_in_state_b,
                    round,
                }
            }
            RumorState::D => RumorState::D,
        }
    }

    /// We only need to push and pull this rumor if we're in states B or C, hence this returns
    /// `None` if we're in state D.  State C is indicated by returning a value > `max_b_age`.
    pub fn our_age(&self) -> Option<u8> {
        match *self {
            RumorState::B { our_age, .. } => Some(our_age),
            RumorState::C { .. } => Some(u8::max_value()),
            RumorState::D => None,
        }
    }
}
