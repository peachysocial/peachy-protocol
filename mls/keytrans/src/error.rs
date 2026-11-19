// SPDX-License-Identifier: MIT
//! The crate's one error type.
//!
//! The variants say which kind of thing went wrong, never which label, key or
//! account it was about: an error may end up in a log line.

/// Everything this crate can refuse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Bytes that do not decode as the structure asked for, or decode with
    /// bytes left over.
    #[error("malformed encoding: {0}")]
    Decode(String),
    /// A structure that cannot be encoded: a vector longer than its length
    /// prefix allows, or a field outside its declared bounds.
    #[error("cannot encode: {0}")]
    Encode(&'static str),
    /// A public key that is not a valid point, is of small order, or is not
    /// in canonical form.
    #[error("invalid public key")]
    InvalidKey,
    /// An Ed25519 signature that does not verify.
    #[error("bad signature")]
    BadSignature,
    /// A VRF proof that does not verify.
    #[error("bad VRF proof")]
    BadVrfProof,
    /// A Merkle proof (log tree, prefix tree or device set) that is
    /// structurally wrong: the wrong number of elements, a position outside
    /// the tree, two values for one node.
    #[error("malformed proof: {0}")]
    MalformedProof(&'static str),
    /// A proof that is well formed but evaluates to a value other than the
    /// one it had to reach, such as a retained subtree head.
    #[error("proof does not match: {0}")]
    ProofMismatch(&'static str),
    /// An argument outside what the function accepts.
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
    /// The prover's storage failed, or returned something missing or
    /// inconsistent (feature `prover`): a node, entry or record it must hold.
    #[error("storage: {0}")]
    Storage(String),
}

/// The crate's result type.
pub type Result<T> = core::result::Result<T, Error>;

impl From<tls_codec::Error> for Error {
    fn from(err: tls_codec::Error) -> Self {
        Error::Decode(err.to_string())
    }
}
