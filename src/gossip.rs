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

use std::collections::{BTreeMap, BTreeSet};
use tiny_keccak::sha3_256;

/// SHA3-256 hash digest.
pub type Digest256 = [u8; 32];

/// Gossip protocol handler
pub struct Gossip {
    messages: BTreeMap<Digest256, (bool, String)>,
}

impl Gossip {
    pub fn new() -> Self {
        Gossip { messages: BTreeMap::new() }
    }

    pub fn get_messages(&self) -> Vec<String> {
        self.messages.values().map(|v| v.1.clone()).collect()
    }

    pub fn inform_or_receive(&mut self, msg: String) {
        let msg_hash = sha3_256(msg.as_bytes());
        let _ = self.messages.entry(msg_hash).or_insert((true, msg));
    }

    pub fn get_hot_msg_hash_list(&self) -> BTreeSet<Digest256> {
        self.messages
            .iter()
            .filter_map(|(k, v)| if v.0 { Some(k) } else { None })
            .cloned()
            .collect()
    }

    /// (already_had_msg_hash_list, peer_may_need_msg_hash_list)
    pub fn handle_push(
        &self,
        hot_msg_hash_list: &BTreeSet<Digest256>,
    ) -> (BTreeSet<Digest256>, BTreeSet<Digest256>) {
        let own_hot_msg_hash_list: BTreeSet<Digest256> = self.messages
            .iter()
            .filter_map(|(k, v)| if v.0 { Some(k) } else { None })
            .cloned()
            .collect();
        let own_msg_hash_list: BTreeSet<Digest256> = self.messages.keys().cloned().collect();
        (
            hot_msg_hash_list
                .intersection(&own_msg_hash_list)
                .cloned()
                .collect(),
            own_hot_msg_hash_list
                .difference(hot_msg_hash_list)
                .cloned()
                .collect(),
        )
    }

    /// (messages_pushed_to_peer, messages_I_need)
    pub fn handle_push_response(
        &mut self,
        already_had_msg_hash_list: &BTreeSet<Digest256>,
        you_may_need_msg_hash_list: &BTreeSet<Digest256>,
    ) -> (Vec<String>, BTreeSet<Digest256>) {
        for hash in already_had_msg_hash_list {
            if let Some(v) = self.messages.get_mut(hash) {
                v.0 = false;
            }
        }
        let pushed_messages: Vec<String> = self.messages
            .values()
            .filter_map(|v| if v.0 { Some(v.1.clone()) } else { None })
            .collect();
        let own_msg_hash_list: BTreeSet<Digest256> = self.messages.keys().cloned().collect();
        (
            pushed_messages,
            you_may_need_msg_hash_list
                .difference(&own_msg_hash_list)
                .cloned()
                .collect(),
        )
    }

    pub fn handle_pull(&mut self, messages_peer_need: &BTreeSet<Digest256>) -> Vec<String> {
        self.messages
            .iter()
            .filter_map(|(k, v)| if messages_peer_need.contains(k) {
                Some(v.1.clone())
            } else {
                None
            })
            .collect()
    }
}
