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

use ed25519_dalek::{Keypair, PublicKey, Signature};
use error::Error;
use maidsafe_utilities::serialisation;
#[cfg(not(test))]
use sha3::Sha3_512;

/// Messages sent via a direct connection, wrapper of gossip protocol rpcs.
#[derive(Serialize, Debug, Deserialize)]
pub struct Message(pub Vec<u8>, pub Signature);

#[cfg(not(test))]
impl Message {
    pub fn serialise(rpc: &GossipRpc, keys: &Keypair) -> Result<Vec<u8>, Error> {
        let str = serialisation::serialise(rpc)?;
        let sig: Signature = keys.sign::<Sha3_512>(&str);
        Ok(serialisation::serialise(&Message(str, sig))?)
    }

    pub fn deserialise(message: &[u8], key: &PublicKey) -> Result<GossipRpc, Error> {
        let msg: Message = serialisation::deserialise(message)?;
        if key.verify::<Sha3_512>(&msg.0, &msg.1) {
            Ok(serialisation::deserialise(&msg.0)?)
        } else {
            Err(Error::SigFailure)
        }
    }
}

#[cfg(test)]
impl Message {
    pub fn serialise(rpc: &GossipRpc, _keys: &Keypair) -> Result<Vec<u8>, Error> {
        Ok(serialisation::serialise(rpc)?)
    }

    pub fn deserialise(message: &[u8], _key: &PublicKey) -> Result<GossipRpc, Error> {
        Ok(serialisation::deserialise(message)?)
    }
}

/// Gossip rpcs
#[derive(Serialize, Debug, Deserialize)]
pub enum GossipRpc {
    /// Sent from Node A to Node B to push a message and its counter.
    Push(u8, Vec<u8>),
    /// Node A pull fom Node B.
    Pull,
}
