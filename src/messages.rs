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

use gossip::Digest256;
use std::collections::BTreeSet;

/// Messages sent via a direct connection, wrapper of gossip protocol rpcs.
#[derive(Serialize, Deserialize)]
pub enum Message {
    /// Sent a message from one node to another.
    Message(String),
    /// Sent from Node A to Node B to notify a list of hot messages.
    Push(BTreeSet<Digest256>),
    /// Sent from Node B to Node A on receiving a push notification.
    /// Contains the list of message hash that already have,
    /// and the list of message hash that node B thinks node A may needed.
    PushResponse {
        already_had_msg_hash_list: BTreeSet<Digest256>,
        peer_may_need_msg_hash_list: BTreeSet<Digest256>,
    },
    /// Sent from Node A to Node B on receiving a PushResponse.
    /// Contains the list of hash that node A wants to fetch messages from node B.
    Pull(BTreeSet<Digest256>),
}
