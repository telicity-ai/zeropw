//! ZeroPW trusted process, ported from the Python prototype in `zeropw/`.
//!
//! Each module mirrors the Python module of the same name; `PORTING.md` holds
//! the equivalence contract. Modules outside the first-half scope (tools,
//! runs, server, incident, intrusion, notify, CLIs, demo) are not ported yet.

#![deny(unsafe_code)]

pub mod clock;
pub mod errors;
pub mod secret;

pub mod pyjson;
pub mod store;

pub mod crypto;
pub mod kms;

pub mod audit;
pub mod handles;
pub mod projects;

pub mod policy;
pub mod vault;

pub mod context;

pub mod gateway;
pub mod sshwire;
pub mod signer;

pub mod fake_upstream;

pub mod team;

#[cfg(test)]
pub(crate) mod oracle;

pub use errors::{Error, ErrorClass, Result};
