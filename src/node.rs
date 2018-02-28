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

use ed25519_dalek::{PUBLIC_KEY_LENGTH, PublicKey};
use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};

/// An peer node on the network.
pub struct Node {
    key: PublicKey,
}

impl Node {
    /// Construct a new `Node` with the given `key`.
    pub fn _new(key: PublicKey) -> Self {
        Node { key }
    }

    /// The ID of this `Node`, i.e. its public key.
    pub fn id(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.key.as_bytes()
    }
}

impl PartialEq<Self> for Node {
    fn eq(&self, other: &Self) -> bool {
        self.key.eq(&other.key)
    }
}

impl Eq for Node {}

impl PartialOrd<Self> for Node {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.key.as_bytes().partial_cmp(other.key.as_bytes())
    }
}

impl Ord for Node {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.as_bytes().cmp(other.key.as_bytes())
    }
}

impl Debug for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "{:02x}{:02x}{:02x}..",
            self.id()[0],
            self.id()[1],
            self.id()[2]
        )
    }
}
