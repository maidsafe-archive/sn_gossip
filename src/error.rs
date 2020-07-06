// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use err_derive::Error;

/// Node error variants.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error(display = "Gossip group empty")]
    NoPeers,
    #[error(display = "Already started gossiping.")]
    AlreadyStarted,
    #[error(display = "Failed to verify signature.")]
    SigFailure,
    #[error(display = "IO error")]
    Io(#[error(cause)] ::std::io::Error),
    #[error(display = "Serialisation Error.")]
    Serialisation(#[error(cause)] Box<bincode::ErrorKind>),
}
