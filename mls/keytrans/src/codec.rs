// SPDX-License-Identifier: MIT
//! TLS presentation-language encoding, as draft-ietf-keytrans-protocol-05
//! §2.1 uses it, on top of `tls_codec`'s traits and derive.
//!
//! # Vector lengths count elements
//!
//! RFC 8446 §3.4 prefixes a vector with its length in bytes. Read that way,
//! several of the draft's vectors could not hold what they must: a
//! `BinaryLadderStep binary_ladder<0..2^8-1>` would fit two steps, and a
//! `PrefixProof prefix_proofs<0..2^8-1>` not even one proof of any depth. The
//! draft's editor's own implementation prefixes every vector with its number
//! of ELEMENTS, and so does this crate. For `opaque` vectors the two readings
//! agree: one element is one byte.
//!
//! `tls_codec`'s own vector types prefix the byte length, so the counted
//! vectors here are `with` modules for the derive (`#[tls_codec(with =
//! "crate::codec::v8")]`). Byte strings use the `b*` modules so every field
//! of the public structures is a plain `Vec`.
//!
//! An `optional<T>` is `Option<T>`: `tls_codec` writes the presence octet and
//! refuses any value other than 0 or 1, as §2.1 requires.

use std::io::{Read, Write};

use tls_codec::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Encodes a structure to its TLS presentation-language bytes.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    value
        .tls_serialize_detached()
        .map_err(|_| Error::Encode("structure does not fit its length prefixes"))
}

/// Decodes a structure from exactly `bytes`: trailing bytes are an error.
pub fn decode<T: Deserialize>(bytes: &[u8]) -> Result<T> {
    T::tls_deserialize_exact(bytes).map_err(Error::from)
}

/// Writes a length prefix of `width` bytes, refusing a length above `max`.
fn write_len<W: Write>(
    len: usize,
    width: usize,
    max: u64,
    writer: &mut W,
) -> core::result::Result<usize, tls_codec::Error> {
    let len = u64::try_from(len).map_err(|_| tls_codec::Error::InvalidVectorLength)?;
    if len > max {
        return Err(tls_codec::Error::InvalidVectorLength);
    }
    let bytes = len.to_be_bytes();
    let start = bytes.len().saturating_sub(width);
    let prefix = bytes.get(start..).ok_or(tls_codec::Error::LibraryError)?;
    writer
        .write_all(prefix)
        .map_err(|e| tls_codec::Error::EncodingError(e.to_string()))?;
    Ok(width)
}

/// Reads a length prefix of `width` bytes.
fn read_len<R: Read>(width: usize, reader: &mut R) -> core::result::Result<u64, tls_codec::Error> {
    let mut buf = [0u8; 8];
    let start = buf.len().saturating_sub(width);
    let slot = buf.get_mut(start..).ok_or(tls_codec::Error::LibraryError)?;
    reader
        .read_exact(slot)
        .map_err(|_| tls_codec::Error::EndOfStream)?;
    Ok(u64::from_be_bytes(buf))
}

/// Reads exactly `len` bytes without trusting `len` for an allocation.
fn read_bytes<R: Read>(
    len: u64,
    reader: &mut R,
) -> core::result::Result<Vec<u8>, tls_codec::Error> {
    let mut out = Vec::new();
    let got = reader
        .take(len)
        .read_to_end(&mut out)
        .map_err(|_| tls_codec::Error::EndOfStream)?;
    if u64::try_from(got).map_err(|_| tls_codec::Error::EndOfStream)? != len {
        return Err(tls_codec::Error::EndOfStream);
    }
    Ok(out)
}

macro_rules! counted_vector {
    ($name:ident, $width:literal, $max:expr, $doc:literal) => {
        #[doc = $doc]
        pub mod $name {
            use std::io::{Read, Write};

            use tls_codec::{Deserialize, Serialize, Size};

            /// Encoded length: the prefix plus every element.
            #[allow(clippy::ptr_arg)]
            pub fn tls_serialized_len<T: Size>(v: &Vec<T>) -> usize {
                v.iter().fold($width, |acc: usize, e| {
                    acc.saturating_add(e.tls_serialized_len())
                })
            }

            /// Writes the element count, then each element.
            #[allow(clippy::ptr_arg)]
            pub fn tls_serialize<T: Serialize, W: Write>(
                v: &Vec<T>,
                writer: &mut W,
            ) -> core::result::Result<usize, tls_codec::Error> {
                let mut written = super::write_len(v.len(), $width, $max, writer)?;
                for e in v {
                    written = written.saturating_add(e.tls_serialize(writer)?);
                }
                Ok(written)
            }

            /// Reads the element count, then that many elements.
            pub fn tls_deserialize<T: Deserialize, R: Read>(
                reader: &mut R,
            ) -> core::result::Result<Vec<T>, tls_codec::Error> {
                let count = super::read_len($width, reader)?;
                // No capacity from `count`: a short input fails at its end,
                // not after a large allocation.
                let mut out = Vec::new();
                for _ in 0..count {
                    out.push(T::tls_deserialize(reader)?);
                }
                Ok(out)
            }
        }
    };
}

macro_rules! byte_vector {
    ($name:ident, $width:literal, $max:expr, $doc:literal) => {
        #[doc = $doc]
        pub mod $name {
            use std::io::{Read, Write};

            /// Encoded length: the prefix plus the bytes.
            #[allow(clippy::ptr_arg)]
            pub fn tls_serialized_len(v: &Vec<u8>) -> usize {
                v.len().saturating_add($width)
            }

            /// Writes the length, then the bytes.
            #[allow(clippy::ptr_arg)]
            pub fn tls_serialize<W: Write>(
                v: &Vec<u8>,
                writer: &mut W,
            ) -> core::result::Result<usize, tls_codec::Error> {
                let written = super::write_len(v.len(), $width, $max, writer)?;
                writer
                    .write_all(v)
                    .map_err(|e| tls_codec::Error::EncodingError(e.to_string()))?;
                Ok(written.saturating_add(v.len()))
            }

            /// Reads the length, then the bytes.
            pub fn tls_deserialize<R: Read>(
                reader: &mut R,
            ) -> core::result::Result<Vec<u8>, tls_codec::Error> {
                let len = super::read_len($width, reader)?;
                super::read_bytes(len, reader)
            }
        }
    };
}

counted_vector!(
    v8,
    1,
    0xff,
    "`T items<0..2^8-1>`: a one-byte element count."
);
counted_vector!(
    v16,
    2,
    0xffff,
    "`T items<0..2^16-1>`: a two-byte element count."
);
counted_vector!(
    v32,
    4,
    0xffff_ffff,
    "`T items<0..2^32-1>`: a four-byte element count."
);
byte_vector!(b8, 1, 0xff, "`opaque data<0..2^8-1>`: a one-byte length.");
byte_vector!(
    b16,
    2,
    0xffff,
    "`opaque data<0..2^16-1>`: a two-byte length."
);
byte_vector!(
    b32,
    4,
    0xffff_ffff,
    "`opaque data<0..2^32-1>`: a four-byte length."
);

/// The writer half of a hand-written encoding: appends fields in order and
/// remembers the first field that did not fit.
#[derive(Default)]
pub(crate) struct Writer {
    out: Vec<u8>,
    failed: Option<&'static str>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.out.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub(crate) fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.out.extend_from_slice(v);
        self
    }

    /// `opaque data<min..max>` with a length prefix of the width `max` needs.
    pub(crate) fn bytes(
        &mut self,
        v: &[u8],
        min: usize,
        max: usize,
        what: &'static str,
    ) -> &mut Self {
        if v.len() < min || v.len() > max {
            self.failed.get_or_insert(what);
            return self;
        }
        let len = v.len();
        if max <= 0xff {
            self.out.push(len as u8);
        } else if max <= 0xffff {
            self.out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            self.out.extend_from_slice(&(len as u32).to_be_bytes());
        }
        self.out.extend_from_slice(v);
        self
    }

    pub(crate) fn finish(&mut self) -> Result<Vec<u8>> {
        match self.failed {
            Some(what) => Err(Error::Encode(what)),
            None => Ok(core::mem::take(&mut self.out)),
        }
    }
}

/// The reader half: consumes fields in order from a byte slice.
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.rest.len() < n {
            return Err(Error::Decode("unexpected end of input".into()));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        let b = self.take(1)?;
        b.first()
            .copied()
            .ok_or_else(|| Error::Decode("unexpected end of input".into()))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let arr: [u8; 8] = b
            .try_into()
            .map_err(|_| Error::Decode("unexpected end of input".into()))?;
        Ok(u64::from_be_bytes(arr))
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let b = self.take(N)?;
        b.try_into()
            .map_err(|_| Error::Decode("unexpected end of input".into()))
    }

    /// `opaque data<min..max>`, the counterpart of [`Writer::bytes`].
    pub(crate) fn bytes(&mut self, min: usize, max: usize, what: &'static str) -> Result<&'a [u8]> {
        let len = if max <= 0xff {
            usize::from(self.u8()?)
        } else if max <= 0xffff {
            let b: [u8; 2] = self.array()?;
            usize::from(u16::from_be_bytes(b))
        } else {
            let b: [u8; 4] = self.array()?;
            usize::try_from(u32::from_be_bytes(b)).map_err(|_| Error::Decode(what.into()))?
        };
        if len < min || len > max {
            return Err(Error::Decode(what.into()));
        }
        self.take(len)
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::Decode("trailing bytes".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

    use super::*;

    #[derive(Debug, PartialEq, TlsSerialize, TlsDeserialize, TlsSize)]
    struct Sample {
        #[tls_codec(with = "crate::codec::v8")]
        words: Vec<u16>,
        #[tls_codec(with = "crate::codec::b16")]
        blob: Vec<u8>,
        maybe: Option<u32>,
    }

    #[test]
    fn counted_vectors_prefix_the_element_count() {
        let s = Sample {
            words: vec![0x0102, 0x0304, 0x0506],
            blob: vec![0xaa, 0xbb],
            maybe: Some(7),
        };
        let bytes = encode(&s).unwrap();
        assert_eq!(
            hex::encode(&bytes),
            // 3 elements, not 6 bytes; then a 2-byte length; then present 7.
            "03010203040506".to_owned() + "0002aabb" + "0100000007"
        );
        assert_eq!(decode::<Sample>(&bytes).unwrap(), s);
    }

    #[test]
    fn decode_refuses_trailing_bytes_and_bad_presence() {
        let s = Sample {
            words: vec![],
            blob: vec![],
            maybe: None,
        };
        let mut bytes = encode(&s).unwrap();
        assert_eq!(hex::encode(&bytes), "00000000");
        bytes.push(0);
        assert!(decode::<Sample>(&bytes).is_err());
        // Presence octet 2.
        assert!(decode::<Sample>(&[0x00, 0x00, 0x00, 0x02]).is_err());
    }

    #[test]
    fn encode_refuses_an_overlong_vector() {
        let s = Sample {
            words: vec![0; 256],
            blob: vec![],
            maybe: None,
        };
        assert!(encode(&s).is_err());
        let s = Sample {
            words: vec![0; 255],
            blob: vec![],
            maybe: None,
        };
        assert!(encode(&s).is_ok());
    }

    #[test]
    fn short_input_with_a_huge_count_fails_cleanly() {
        // A count of 255 elements with nothing after it.
        assert!(decode::<Sample>(&[0xff]).is_err());
        // A blob length of 65535 with two bytes after it.
        assert!(decode::<Sample>(&[0x00, 0xff, 0xff, 0x01, 0x02]).is_err());
    }
}
