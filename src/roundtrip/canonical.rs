//! Small, bounded canonical binary encoding for keyed inputs.

use super::{Error, Result};

pub const DEFAULT_MAX_CANONICAL_BYTES: usize = 1024 * 1024;

/// A deterministic length-prefixed binary writer.
pub struct CanonicalWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl CanonicalWriter {
    /// Starts a canonical record with one explicit ASCII domain.
    pub fn new(domain: &str, limit: usize) -> Result<Self> {
        if domain.is_empty() || !domain.is_ascii() || limit > DEFAULT_MAX_CANONICAL_BYTES {
            return Err(Error::InvalidCanonicalInput);
        }
        let mut writer = Self {
            bytes: Vec::new(),
            limit,
        };
        writer.bytes(domain.as_bytes())?;
        Ok(writer)
    }

    pub fn u8(&mut self, value: u8) -> Result<()> {
        self.extend(&[value])
    }

    pub fn u16(&mut self, value: u16) -> Result<()> {
        self.extend(&value.to_be_bytes())
    }

    pub fn u32(&mut self, value: u32) -> Result<()> {
        self.extend(&value.to_be_bytes())
    }

    pub fn u64(&mut self, value: u64) -> Result<()> {
        self.extend(&value.to_be_bytes())
    }

    /// Suite-specific fixed-width little-endian integer. Candidate identity uses this
    /// only for Windows `FILE_ID_INFO.VolumeSerialNumber`.
    pub(crate) fn u64_le(&mut self, value: u64) -> Result<()> {
        self.extend(&value.to_le_bytes())
    }

    pub fn bytes(&mut self, value: &[u8]) -> Result<()> {
        let length = u32::try_from(value.len()).map_err(|_| Error::BoundExceeded)?;
        self.u32(length)?;
        self.extend(value)
    }

    pub fn ascii(&mut self, value: &str) -> Result<()> {
        if !value.is_ascii() {
            return Err(Error::InvalidCanonicalInput);
        }
        self.bytes(value.as_bytes())
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn extend(&mut self, value: &[u8]) -> Result<()> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(Error::BoundExceeded)?;
        if next > self.limit {
            return Err(Error::BoundExceeded);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_writer_is_unambiguous_and_bounded() {
        let mut writer = CanonicalWriter::new("example", 64).expect("valid domain");
        writer.u16(1).expect("integer fits");
        writer.bytes(b"ab").expect("bytes fit");
        assert_eq!(writer.finish(), b"\0\0\0\x07example\0\x01\0\0\0\x02ab");

        let mut bounded = CanonicalWriter::new("x", 6).expect("domain fits");
        assert_eq!(bounded.bytes(b"z"), Err(Error::BoundExceeded));
    }
}
