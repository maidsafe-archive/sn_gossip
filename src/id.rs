// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use ed25519_dalek::{PublicKey, PUBLIC_KEY_LENGTH};
use std::convert::From;
use std::fmt::{self, Debug, Formatter};

/// The ID of a node - equivalent to its public key.
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Id(pub [u8; PUBLIC_KEY_LENGTH]);

impl From<PublicKey> for Id {
    fn from(key: PublicKey) -> Self {
        Id(key.to_bytes())
    }
}

impl Debug for Id {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:02x}{:02x}{:02x}..",
            self.0[0], self.0[1], self.0[2]
        )
    }
}
