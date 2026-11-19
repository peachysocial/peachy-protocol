// SPDX-License-Identifier: MIT
//! [`Secret`]: a secret value that is wiped when it drops and that `Debug`
//! prints only as its length. A type holding its secrets in `Secret` fields
//! may derive `Debug`, and printing it shows no secret.

use zeroize::{Zeroize, Zeroizing};

/// A secret value: wiped when it drops, and printed by `Debug` as its length
/// alone. Reads as its value through `Deref`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret<T: Zeroize>(Zeroizing<T>);

impl<T: Zeroize> Secret<T> {
    /// Wrap `value`, which is wiped from then on.
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize> std::ops::Deref for Secret<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> std::ops::DerefMut for Secret<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// How many elements a secret holds, which is all its `Debug` shows.
pub trait SecretLen {
    fn secret_len(&self) -> usize;
}

impl<E> SecretLen for Vec<E> {
    fn secret_len(&self) -> usize {
        self.len()
    }
}

impl<E, const N: usize> SecretLen for [E; N] {
    fn secret_len(&self) -> usize {
        N
    }
}

impl SecretLen for String {
    fn secret_len(&self) -> usize {
        self.len()
    }
}

impl<T: Zeroize + SecretLen> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(len {})", self.0.secret_len())
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_prints_the_length_alone() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            epoch: u64,
            key: Secret<[u8; 4]>,
            words: Secret<Vec<u8>>,
        }
        let holder = Holder {
            epoch: 9,
            key: Secret::new([0xAB; 4]),
            words: Secret::new(b"the words".to_vec()),
        };
        let printed = format!("{holder:?} {holder:#?}");
        assert!(printed.contains("Secret(len 4)") && printed.contains("Secret(len 9)"));
        assert!(!printed.contains("171") && !printed.contains("116, 104"));
    }
}
