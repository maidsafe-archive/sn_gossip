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

//! Run a local network of gossiper nodes.

#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        stable_features, unconditional_recursion, unknown_lints, unsafe_code, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true, unused)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, missing_copy_implementations, missing_debug_implementations,
         variant_size_differences, non_camel_case_types)]

extern crate itertools;
extern crate rand;
extern crate safe_gossip;
#[macro_use]
extern crate unwrap;

use itertools::Itertools;
use rand::Rng;
use safe_gossip::{Error, Gossiper};

struct Network {
    nodes: Vec<Gossiper>,
    // All messages sent in the order they were passed in.  Tuple contains the message and the index
    // of the node used to send.
    messages: Vec<(String, usize)>,
}

impl Network {
    fn new(node_count: usize) -> Self {
        let mut nodes = itertools::repeat_call(Gossiper::default)
            .take(node_count)
            .collect_vec();
        nodes.sort_by(|lhs, rhs| lhs.id().cmp(rhs.id()));
        Network {
            nodes,
            messages: vec![],
        }
    }

    /// Send the given `message`.  If `node_index` is `Some` and is less than the number of `Node`s
    /// in the `Network`, then the `Node` at that index will be chosen as the initial informed one.
    pub fn send(&mut self, message: &str, node_index: Option<usize>) -> Result<(), Error> {
        let count = match node_index {
            Some(index) if index < self.nodes.len() => index,
            _ => rand::thread_rng().gen_range(0, self.nodes.len()),
        };
        self.messages.push((message.to_string(), count));
        self.nodes[count].send_new(message)
    }
}

fn main() {
    let mut network = Network::new(8);
    println!("Nodes: {:?}", network.nodes);
    unwrap!(network.send("Hello", None));
    unwrap!(network.send("there", Some(999)));
    unwrap!(network.send("world", Some(0)));
    println!("Messages: {:?}", network.messages);
}
