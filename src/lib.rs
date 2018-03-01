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

//! An implementation of a push-pull gossip protocol.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "https://maidsafe.net/img/favicon.ico",
       html_root_url = "https://docs.rs/safe_gossip")]

#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        stable_features, unconditional_recursion, unknown_lints, unsafe_code, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true, unused)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, missing_copy_implementations, missing_debug_implementations,
         unused_extern_crates, variant_size_differences, non_camel_case_types)]

extern crate ed25519_dalek;
extern crate futures;
extern crate maidsafe_utilities;
#[macro_use]
extern crate quick_error;
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sha3;
extern crate tiny_keccak;
#[macro_use]
extern crate unwrap;

mod error;
mod gossip;
mod gossiper;
mod id;
mod messages;
mod node;

pub use error::Error;
pub use gossiper::Gossiper;
pub use id::Id;
