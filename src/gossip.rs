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

use std::cmp;
use std::collections::BTreeMap;
use tiny_keccak::sha3_256;

/// SHA3-256 hash digest.
pub type Digest256 = [u8; 32];

/// Gossip protocol handler
pub struct Gossip {
    messages: BTreeMap<Digest256, (u8, String)>,
    total_peers: u64,
    hot_rounds: u8,
    cold_rounds: u8,
}

impl Gossip {
    pub fn new() -> Self {
        Gossip {
            messages: BTreeMap::new(),
            total_peers: 0,
            hot_rounds: 0,
            cold_rounds: 0,
        }
    }

    pub fn add_peer(&mut self) {
        self.total_peers += 1;
        let f = self.total_peers as f64;
        self.hot_rounds = cmp::max(1, f.ln() as u8);
        self.cold_rounds = cmp::max(2, 2 * self.hot_rounds);
    }

    pub fn get_messages(&self) -> Vec<String> {
        self.messages.values().map(|v| v.1.clone()).collect()
    }

    pub fn inform(&mut self, msg: String) {
        let msg_hash = sha3_256(msg.as_bytes());
        let _ = self.messages.entry(msg_hash).or_insert((0, msg));
    }

    pub fn receive(&mut self, count: u8, msg: String) {
        let msg_hash = sha3_256(msg.as_bytes());
        let entry = self.messages.entry(msg_hash).or_insert((count, msg));
        if entry.0 < count {
            entry.0 = count;
        }
    }

    pub fn get_push_list(&mut self) -> Vec<(u8, String)> {
        let push_list: Vec<(u8, String)> = self.messages
            .iter()
            .filter_map(|(_k, v)| if v.0 <= self.hot_rounds {
                Some(v)
            } else {
                None
            })
            .cloned()
            .collect();
        for (_k, v) in self.messages.iter_mut() {
            if v.0 <= self.cold_rounds {
                v.0 += 1;
            }
        }
        push_list
    }

    pub fn handle_pull(&self) -> Vec<(u8, String)> {
        self.messages
            .iter()
            .filter_map(|(_k, v)| if v.0 > self.hot_rounds &&
                v.0 <= self.cold_rounds
            {
                Some(v)
            } else {
                None
            })
            .cloned()
            .collect()
    }
}
