// SPDX-License-Identifier: MIT
//! Key transparency for Peachy: the verifier and prover of a public, audited
//! log of every account's keys, built on
//! draft-ietf-keytrans-protocol-05 in third-party auditing mode. No client
//! uses it and Peachy runs no log.
//!
//! No I/O, no async, no clock and no randomness: timestamps and commitment
//! openings come in as arguments, so the same code can run in the MLS core
//! on a client, and as wasm in Node for the log (feature `prover`) and the
//! auditor (feature `auditor`).
//!

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![warn(missing_docs)]

pub mod codec;
pub mod commitment;
pub mod error;
pub mod head;
pub mod implicit;
pub mod ladder;
pub mod log_tree;
pub mod prefix_proof;
pub mod profile;
pub mod suite;
pub mod verify;
pub mod vrf;
pub mod wire;

#[cfg(any(test, feature = "prover"))]
pub mod prefix_tree;
#[cfg(any(test, feature = "prover"))]
pub mod prover;

#[cfg(any(test, feature = "auditor"))]
pub mod auditor;

pub use error::{Error, Result};
pub use suite::{CipherSuite, Hash};
