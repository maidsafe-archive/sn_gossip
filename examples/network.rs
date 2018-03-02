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

extern crate bytes;
#[macro_use]
extern crate futures;
extern crate futures_cpupool;
extern crate itertools;
extern crate maidsafe_utilities;
extern crate rand;
extern crate safe_gossip;
extern crate tokio;
#[macro_use]
extern crate tokio_io;
#[macro_use]
extern crate unwrap;

use bytes::{BufMut, BytesMut};
use futures::{Async, Future, Poll};
use futures::stream::Stream;
use futures::sync::mpsc;
use futures_cpupool::{CpuFuture, CpuPool};
use maidsafe_utilities::serialisation;
use rand::Rng;
use safe_gossip::{Error, Gossiper, Id};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};
use std::io::Write;
use std::mem;
use std::rc::Rc;
use std::thread;
use tokio::executor::current_thread;
use tokio::net::{TcpListener, TcpStream};
use tokio_io::AsyncRead;

/// TCP stream wrapper presenting a message-based read / write interface.
#[derive(Debug)]
struct MessageStream {
    tcp_stream: TcpStream,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    incoming_message_length: Option<usize>,
}

impl MessageStream {
    fn new(tcp_stream: TcpStream) -> Self {
        MessageStream {
            tcp_stream,
            read_buffer: BytesMut::new(),
            write_buffer: BytesMut::new(),
            incoming_message_length: None,
        }
    }

    /// Buffer `message` to an internal buffer.  Calls to `poll_flush` will attempt to flush this
    /// buffer to the TCP stream.  The size of `message` as a `u32` is added to the buffer first so
    /// that the correct size can be read by the receiver before it tries to retrieve the actual
    /// message.
    fn buffer(&mut self, message: &[u8]) {
        let serialised_length = unwrap!(serialisation::serialise(&(message.len() as u32)));
        if self.write_buffer.remaining_mut() < serialised_length.len() + message.len() {
            self.write_buffer.extend_from_slice(&serialised_length);
            self.write_buffer.extend_from_slice(message);
        } else {
            self.write_buffer.put(&serialised_length);
            self.write_buffer.put(message);
        }

    }

    /// Flush the write buffer to the TCP stream.
    fn poll_flush(&mut self) -> Poll<(), Error> {
        while !self.write_buffer.is_empty() {
            // `try_nb` is kind of like `try_ready`, but for operations that return `io::Result`
            // instead of `Async`.  In the case of `io::Result`, an error of `WouldBlock` is
            // equivalent to `Async::NotReady`.
            let num_bytes = try_nb!(self.tcp_stream.write(&self.write_buffer));
            assert!(num_bytes > 0);
            // Discard the first `num_bytes` bytes of the buffer.
            let _ = self.write_buffer.split_to(num_bytes);
        }

        Ok(Async::Ready(()))
    }

    /// Read data from the TCP stream.  This only returns `Ready` when the socket has closed.
    fn fill_read_buffer(&mut self) -> Poll<(), Error> {
        loop {
            self.read_buffer.reserve(1024);
            let num_bytes = try_ready!(self.tcp_stream.read_buf(&mut self.read_buffer));
            if num_bytes == 0 {
                return Ok(Async::Ready(()));
            }
        }
    }
}

impl Stream for MessageStream {
    type Item = BytesMut;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // First, read any new data that might have been received off the TCP stream
        let socket_closed = self.fill_read_buffer()?.is_ready();

        // If we're not part way through reading an incoming message, read the next incoming
        // message's length.
        if self.incoming_message_length.is_none() && self.read_buffer.len() >= 4 {
            let length_buffer = self.read_buffer.split_to(4);
            let length = unwrap!(serialisation::deserialise::<u32>(&length_buffer)) as usize;
            self.incoming_message_length = Some(length);
        }

        // If we have the next message's length available, read it.
        if let Some(length) = self.incoming_message_length {
            if self.read_buffer.len() >= length {
                self.incoming_message_length = None;
                return Ok(Async::Ready(Some(self.read_buffer.split_to(length))));
            }
        }

        if socket_closed {
            Ok(Async::Ready(None))
        } else {
            Ok(Async::NotReady)
        }
    }
}



/// This is effectively a container for all the state required to manage a node while the network
/// is running.  `Node` implements `Future` and hence each node is run continuously on a single
/// thread from the threadpool.  When the future returns, the `Node` has completed processing all
/// messages.
struct Node {
    gossiper: Gossiper,
    /// This receives new messages from the `Network` object; equivalent to e.g. a new client event.
    channel_receiver: mpsc::UnboundedReceiver<String>,
    /// Map of peer ID to the wrapped TCP stream connecting us to them.
    peers: HashMap<Id, MessageStream>,
    /// Indicates whether is in a push&pull round
    is_in_round: bool,
}

impl Node {
    fn new(channel_receiver: mpsc::UnboundedReceiver<String>) -> Self {
        Node {
            gossiper: Gossiper::default(),
            channel_receiver,
            peers: HashMap::new(),
            is_in_round: false,
        }
    }

    fn add_peer(&mut self, id: Id, tcp_stream: TcpStream) {
        assert!(
            self.peers
                .insert(id, MessageStream::new(tcp_stream))
                .is_none()
        );
        unwrap!(self.gossiper.add_peer(id));
    }

    fn id(&self) -> Id {
        self.gossiper.id()
    }

    /// Receive all new messages from the `Network` object.
    fn receive_from_channel(&mut self) {
        while let Async::Ready(Some(message)) = unwrap!(self.channel_receiver.poll()) {
            unwrap!(self.gossiper.send_new(&message));
        }
    }

    /// Triggers a new push round
    fn tick(&mut self) {
        if !self.is_in_round {
            self.is_in_round = true;
            let id = self.id();

            let (peer_id, msgs_to_send) = unwrap!(self.gossiper.push_tick());
            let message_stream = unwrap!(self.peers.get_mut(&peer_id));
            // Buffer the messages to be sent.
            for msg in msgs_to_send {
                println!(
                    "{:?} - {:?} About to send message of {} bytes to {:?}",
                    thread::current().id(),
                    id,
                    msg.len(),
                    peer_id
                );
                message_stream.buffer(&msg);
            }
        }
    }

    /// Iterate the peers reading any new messages from their TCP streams.  Removes any peers that
    /// have disconnected.
    fn receive_from_peers(&mut self) {
        let mut disconnected_peers = vec![];
        let mut has_response = false;
        for (peer_id, ref mut message_stream) in &mut self.peers {
            loop {
                match message_stream.poll() {
                    Ok(Async::Ready(Some(message))) => {
                        let msgs_to_send = self.gossiper.handle_received_message(peer_id, &message);
                        // Buffer the messages to be sent back.
                        for msg in msgs_to_send {
                            has_response = true;
                            message_stream.buffer(&msg);
                        }
                    }
                    Ok(Async::Ready(None)) => {
                        // EOF was reached; the remote peer has disconnected.
                        disconnected_peers.push(*peer_id);
                    }
                    Ok(Async::NotReady) => break,
                    Err(error) => {
                        println!("Error reading messages from {:?}: {:?}", peer_id, error);
                        disconnected_peers.push(*peer_id);
                        break;
                    }
                }
            }
        }
        for disconnected_peer in disconnected_peers {
            let _ = unwrap!(self.peers.remove(&disconnected_peer));
        }
        self.is_in_round = has_response;
    }

    /// Iterate the peers flushing the write buffers to the TCP streams.  Removes any peers that
    /// have disconnected.
    fn send_to_peers(&mut self) {
        let mut disconnected_peers = vec![];
        for (peer_id, ref mut message_stream) in &mut self.peers {
            if let Err(error) = message_stream.poll_flush() {
                println!("Error writing messages to {:?}: {:?}", peer_id, error);
                disconnected_peers.push(*peer_id);
            }
        }
        for disconnected_peer in disconnected_peers {
            let _ = unwrap!(self.peers.remove(&disconnected_peer));
        }
    }
}

impl Future for Node {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        self.receive_from_channel();
        self.receive_from_peers();
        self.tick();
        self.send_to_peers();
        // If we have no peers left, there is nothing more for this node to do.
        if self.peers.is_empty() {
            return Ok(Async::Ready(()));
        }
        Ok(Async::NotReady)
    }
}

impl Debug for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self.id())
    }
}



struct Network {
    pool: CpuPool,
    channels_to_nodes: Vec<mpsc::UnboundedSender<String>>,
    node_futures: Vec<CpuFuture<(), Error>>,
    // All messages sent in the order they were passed in.  Tuple contains the message and the index
    // of the node used to send.
    messages: Vec<(String, usize)>,
}

impl Network {
    fn new(node_count: usize) -> Self {
        let (mut nodes, channels_to_nodes): (Vec<_>, Vec<_>) = itertools::repeat_call(|| {
            let (channel_transmitter, channel_receiver) = mpsc::unbounded();
            (Node::new(channel_receiver), channel_transmitter)
        }).take(node_count)
            .unzip();

        nodes.sort_by(|lhs, rhs| lhs.id().cmp(&rhs.id()));
        println!("Nodes: {:?}", nodes);

        let mut network = Network {
            // pool: CpuPool::new(1),
            pool: CpuPool::new_num_cpus(),
            channels_to_nodes,
            node_futures: vec![],
            messages: vec![],
        };

        // Connect all the nodes.
        let listening_address = unwrap!("127.0.0.1:0".parse());
        for i in 0..(node_count - 1) {
            let listener = unwrap!(TcpListener::bind(&listening_address));
            let lhs_id = nodes[i].id();
            let listener_address = unwrap!(listener.local_addr());
            let incoming = Rc::new(RefCell::new(listener.incoming().wait()));
            for j in (i + 1)..node_count {
                let rhs_id = nodes[j].id();
                let rhs_stream = current_thread::run(|_| TcpStream::connect(&listener_address))
                    .wait();
                nodes[j].add_peer(lhs_id, unwrap!(rhs_stream));
                let incoming = incoming.clone();
                let lhs_stream = unwrap!(current_thread::run(|_| incoming.borrow_mut()).next());
                nodes[i].add_peer(rhs_id, unwrap!(lhs_stream));
            }
        }

        // Start the nodes running by executing their `poll()` functions on the threadpool.
        for node in nodes {
            network.node_futures.push(network.pool.spawn(node));
        }

        network
    }

    /// Send the given `message`.  If `node_index` is `Some` and is less than the number of `Node`s
    /// in the `Network`, then the `Node` at that index will be chosen as the initial informed one.
    fn send(&mut self, message: &str, node_index: Option<usize>) -> Result<(), Error> {
        let count = match node_index {
            Some(index) if index < self.channels_to_nodes.len() => index,
            _ => rand::thread_rng().gen_range(0, self.channels_to_nodes.len()),
        };
        self.messages.push((message.to_string(), count));
        unwrap!(self.channels_to_nodes[count].unbounded_send(
            message.to_string(),
        ));
        Ok(())
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        let node_futures = mem::replace(&mut self.node_futures, vec![]);
        for node_future in node_futures {
            unwrap!(node_future.wait());
        }
    }
}



fn main() {
    let mut network = Network::new(8);
    unwrap!(network.send("Hello", None));
    unwrap!(network.send("there", Some(999)));
    unwrap!(network.send("world", Some(0)));
    println!("Messages: {:?}", network.messages);
}
