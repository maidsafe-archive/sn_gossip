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

extern crate futures;
extern crate futures_cpupool;
extern crate itertools;
extern crate rand;
extern crate safe_gossip;
extern crate tokio;
// extern crate tokio_io;
#[macro_use]
extern crate unwrap;

use futures::{Future, lazy};
use futures::future::Executor;
use futures_cpupool::CpuPool;
use itertools::Itertools;
use rand::Rng;
use safe_gossip::{Error, Gossiper, Id};
use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};

struct Node {
    id: Id,
    gossiper: Arc<Mutex<Gossiper>>,
    peers: HashMap<Id, Arc<Mutex<TcpStream>>>,
}

impl Node {
    fn add_peer(&mut self, id: Id, stream: TcpStream) {
        assert!(
            self.peers
                .insert(id, Arc::new(Mutex::new(stream)))
                .is_none()
        );
        unwrap!(unwrap!(self.gossiper.lock()).add_peer(id));
    }

    // fn start(&mut self) {}
}

impl Default for Node {
    fn default() -> Self {
        let gossiper = Gossiper::default();
        let id = gossiper.id();
        Node {
            id,
            gossiper: Arc::new(Mutex::new(gossiper)),
            peers: HashMap::new(),
        }
    }
}

impl Debug for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self.id)
    }
}

struct Network {
    pool: CpuPool,
    nodes: Vec<Node>,
    // All messages sent in the order they were passed in.  Tuple contains the message and the index
    // of the node used to send.
    messages: Vec<(String, usize)>,
}

fn process(
    gossiper: Arc<Mutex<Gossiper>>,
    tcp_stream: Arc<Mutex<TcpStream>>,
    pool: &CpuPool,
    our_id: Id,
    their_id: Id,
) {
    unwrap!(pool.execute(lazy(move || {
        let mut buffer = vec![0u8; 1000];
        let mut tcp_stream = unwrap!(tcp_stream.lock());
        if let Ok(size) = tcp_stream.read(&mut buffer) {
            println!("{:?} Received {} bytes from {:?}", our_id, size, their_id);
            let responses =
                unwrap!(gossiper.lock()).handle_received_message(&their_id, &buffer[0..size]);
            for response in &responses {
                let _ = tcp_stream.write_all(response);
            }
        }
        Ok(())
    })));
}

impl Network {
    fn new(node_count: usize) -> Self {
        let pool = CpuPool::new_num_cpus();
        let mut nodes = itertools::repeat_call(Node::default)
            .take(node_count)
            .collect_vec();
        nodes.sort_by(|lhs, rhs| lhs.id.cmp(&rhs.id));

        // Connect all the nodes.
        let listening_address = unwrap!("127.0.0.1:0".parse());
        for i in 0..(nodes.len() - 1) {
            let listener = unwrap!(TcpListener::bind(&listening_address));
            let lhs_id = nodes[i].id;
            let listener_address = unwrap!(listener.local_addr());
            let listener = Arc::new(Mutex::new(listener));
            for j in (i + 1)..nodes.len() {
                let rhs_id = nodes[j].id;
                let rhs_stream = unwrap!(pool.spawn(TcpStream::connect(&listener_address)).wait());
                nodes[j].add_peer(lhs_id, rhs_stream);
                let listener = listener.clone();
                let (lhs_stream, _) = unwrap!(
                    pool.spawn_fn(move || {
                        let mut listener = unwrap!(listener.lock());
                        listener.accept()
                    }).wait()
                );
                nodes[i].add_peer(rhs_id, lhs_stream);
            }
        }

        Network {
            pool,
            nodes,
            messages: vec![],
        }
    }

    /// Send the given `message`.  If `node_index` is `Some` and is less than the number of `Node`s
    /// in the `Network`, then the `Node` at that index will be chosen as the initial informed one.
    fn send(&mut self, message: &str, node_index: Option<usize>) -> Result<(), Error> {
        let count = match node_index {
            Some(index) if index < self.nodes.len() => index,
            _ => rand::thread_rng().gen_range(0, self.nodes.len()),
        };
        self.messages.push((message.to_string(), count));
        let sender_id = self.nodes[count].id;
        let response = unwrap!(self.nodes[count].gossiper.lock()).send_new(message);
        response.and_then(|(peer_id, to_send)| {
            let stream = unwrap!(self.nodes[count].peers.get_mut(&peer_id));
            for msg in to_send {
                unwrap!(unwrap!(stream.lock()).write_all(&msg));
            }
            println!("{:?} Sent messages to {:?}", sender_id, peer_id);
            Ok(())
        })
    }

    fn poll(&mut self) {
        let mut processed = true;
        while processed {
            processed = false;
            for node in &mut self.nodes {
                println!("Polling node {:?}", node);
                for (peer_id, stream) in &mut node.peers {
                    // let mut buffer = vec![0u8; 1000];
                    println!("Polling peer {:?}", peer_id);
                    process(
                        node.gossiper.clone(),
                        stream.clone(),
                        &self.pool,
                        node.id,
                        *peer_id,
                    );
                    // if let Ok(size) = stream.read(&mut buffer) {
                    //     processed = true;
                    //     println!("Received {} bytes from {:?}", size, peer);
                    //     node.gossiper.handle_received_message(peer, &buffer);
                    //     // let responses = node.gossiper.handle_received_message(peer, &buffer);
                    //     // for response in &responses {
                    //     //     let _ = stream.write_all(response);
                    //     //     // let _ = stream.flush();
                    //     // }
                    // }
                }
            }
        }
    }
}

fn main() {
    let mut network = Network::new(3);
    println!("Nodes: {:?}", network.nodes);
    unwrap!(network.send("Hello", None));
    network.poll();
    unwrap!(network.send("there", Some(999)));
    network.poll();
    unwrap!(network.send("world", Some(0)));
    network.poll();
    println!("Messages: {:?}", network.messages);
    network.poll();
}
