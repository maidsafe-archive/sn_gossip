// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use bincode;

quick_error! {
    /// Gossiper error variants.
    #[derive(Debug)]
    pub enum Error {
        /// No connected peers.
        NoPeers {
            description("No connected peers")
            display("There are no connected peers with which to gossip.")
        }
        /// Already started gossiping.
        AlreadyStarted {
            description("Already started gossiping")
            display("Connections to all other nodes must be made before sending any messages.")
        }
        /// Failed in verify signature.
        SigFailure {
            description("Signature cannot be verified")
            display("The message or signature might be corrupted, or the signer is wrong.")
        }
        /// IO error.
        Io(error: ::std::io::Error) {
            description(error.description())
            display("I/O error: {}", error)
            from()
        }
        /// Serialisation Error.
        Serialisation(error: Box<bincode::ErrorKind>) {
            description(error.description())
            display("Serialisation error: {}", error)
            from()
        }
    }
}
