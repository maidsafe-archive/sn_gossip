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

use id::Id;
use std::collections::{BTreeMap, BTreeSet};
use std::collections::btree_map::Entry;

/// This represents the state of a single message from this node's perspective.
#[derive(Debug)]
pub enum MessageState {
    /// Exponential-growth phase.
    B {
        /// The round number for this message.  This is not a globally-synchronised variable, rather
        /// it is set to 0 when we first receive a copy of this message and is incremented every
        /// time `next_round()` is called.
        round: u8,
        /// Our counter for this message.  This may increase by 1 during a single round or may
        /// remain the same depending on the counters attached to incoming copies of this message.
        our_counter: u8,
        /// The map of <peer, counter>s which have sent us this message during this round.
        peer_counters: BTreeMap<Id, u8>,
    },
    /// Quadratic-shrinking phase.
    C {
        /// The number of rounds performed by the node while the message was in state B.
        rounds_in_state_b: u8,
        /// The round number for this message while in state C.
        round: u8,
    },
    /// Propagation complete.
    D,
}

impl MessageState {
    /// Construct a new `MessageState` where we're the initial node for the message.  We start in
    /// state B with `our_counter` set to `1`.
    pub fn new() -> Self {
        MessageState::B {
            round: 0,
            our_counter: 1,
            peer_counters: BTreeMap::new(),
        }
    }

    /// Construct a new `MessageState` where we've received the message from a peer.  If that peer
    /// is in state B (`counter < counter_max`) we start in state B with `our_counter` set to `1`.
    /// If the peer is in state C, we start in state C too.
    pub fn new_from_peer(counter: u8, counter_max: u8) -> Self {
        if counter < counter_max {
            return MessageState::B {
                round: 0,
                our_counter: 1,
                peer_counters: BTreeMap::new(),
            };
        }
        MessageState::C {
            rounds_in_state_b: 0,
            round: 0,
        }
    }

    /// Receive a copy of this message from `peer_id` with `counter`.
    pub fn receive(&mut self, peer_id: Id, counter: u8) {
        if let MessageState::B { ref mut peer_counters, .. } = *self {
            if peer_counters.insert(peer_id, counter).is_some() {
                debug!("Received the same message more than once this round from a given peer");
            }
        }
    }

    /// Increment `round` value, consuming `self` and returning the new state.
    pub fn next_round(
        self,
        counter_max: u8,
        max_c_rounds: u8,
        max_rounds: u8,
        peers_in_this_round: &BTreeSet<Id>,
    ) -> MessageState {
        match self {
            MessageState::B {
                mut round,
                mut our_counter,
                mut peer_counters,
            } => {
                round += 1;
                // If we've hit the maximum permitted number of rounds, transition to state D
                if round >= max_rounds {
                    return MessageState::D;
                }

                // For any `peers_in_this_round` which aren't accounted for in `peer_counters`, add
                // a counter of `0` for them to indicate they're in state A (i.e. they didn't have
                // the message).
                for peer in peers_in_this_round {
                    if let Entry::Vacant(entry) = peer_counters.entry(*peer) {
                        let _ = entry.insert(0);
                    }
                }

                // Apply the median rule, but if any peer's counter >= `counter_max` (i.e. that peer
                // is in state C), transition to state C.
                let mut less = 0;
                let mut greater_or_equal = 0;
                for peer_counter in peer_counters.values() {
                    if *peer_counter < our_counter {
                        less += 1;
                    } else if *peer_counter >= counter_max {
                        return MessageState::C {
                            rounds_in_state_b: round,
                            round: 0,
                        };
                    } else {
                        greater_or_equal += 1;
                    }
                }
                if greater_or_equal > less {
                    our_counter += 1;
                }

                // If our counter has reached `counter_max`, transition to state C, otherwise remain
                // in state B.
                if our_counter >= counter_max {
                    return MessageState::C {
                        rounds_in_state_b: round,
                        round: 0,
                    };
                }
                MessageState::B {
                    round,
                    our_counter,
                    peer_counters: BTreeMap::new(),
                }
            }
            MessageState::C {
                rounds_in_state_b,
                mut round,
            } => {
                round += 1;
                // If we've hit the maximum permitted number of rounds, transition to state D
                if round + rounds_in_state_b >= max_rounds {
                    return MessageState::D;
                }

                // If we've hit the maximum rounds for remaining in state C, transition to state D.
                if round >= max_c_rounds {
                    return MessageState::D;
                }

                // Otherwise remain in state C.
                MessageState::C {
                    rounds_in_state_b,
                    round,
                }
            }
            MessageState::D => MessageState::D,
        }
    }

    /// We only need to push and pull this message if we're in states B or C, hence this returns
    /// `None` if we're in state D.  State C is indicated by returning a value > `counter_max`.
    pub fn our_counter(&self) -> Option<u8> {
        match *self {
            MessageState::B { our_counter, .. } => Some(our_counter),
            MessageState::C { .. } => Some(u8::max_value()),
            MessageState::D => None,
        }
    }
}
