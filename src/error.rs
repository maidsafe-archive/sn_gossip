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
        /// IO error.
        Io(error: ::std::io::Error) {
            description(error.description())
            display("I/O error: {}", error)
            from()
        }
        /// Serialisation error.
        Serialisation(error: ::maidsafe_utilities::serialisation::SerialisationError) {
            description(error.description())
            display("Serialisation error: {}", error)
            from()
        }
    }
}
