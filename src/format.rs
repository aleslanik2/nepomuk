//! File format (§7): header, signed checkpoint and an append-only chain of signed commits.

use serde::{Deserialize, Serialize};

use crate::crypto::{self, SUITE};
use crate::error::{Error, Result};
use crate::model::{Id, Op, State};

pub const MAGIC: &[u8; 8] = b"NEPOMUK\0";
pub const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 8 + 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointBody {
    pub vault_id: Id,
    pub seq: u64,
    /// Hash of the commit this checkpoint folds (after `compact`); none for the genesis.
    pub folded_head: Option<[u8; 32]>,
    pub time: i64,
    pub state: State,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitBody {
    pub vault_id: Id,
    pub seq: u64,
    pub prev_hash: [u8; 32],
    pub author: Id,
    pub time: i64,
    pub ops: Vec<Op>,
}

/// A signed entry as stored in the file: the exact bytes that were signed plus the signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RawEntry {
    /// The stored CBOR bytes of the envelope.
    pub bytes: Vec<u8>,
    pub envelope: Envelope,
}

impl RawEntry {
    pub fn hash(&self) -> [u8; 32] {
        crypto::sha3(&[b"nepomuk/entry", &self.bytes])
    }

    pub fn from_envelope(envelope: Envelope) -> Self {
        RawEntry {
            bytes: to_cbor(&envelope),
            envelope,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultFile {
    pub vault_id: Id,
    /// Entry 0 is the checkpoint, the rest are commits.
    pub entries: Vec<RawEntry>,
}

pub fn to_cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("CBOR serialization");
    out
}

pub fn from_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|e| Error::format(format!("malformed CBOR: {e}")))
}

impl VaultFile {
    pub fn parse(data: &[u8]) -> Result<VaultFile> {
        if data.len() < HEADER_LEN || &data[..8] != MAGIC {
            return Err(Error::format("not a nepomuk vault file"));
        }
        let version = u16::from_be_bytes([data[8], data[9]]);
        if version != FORMAT_VERSION {
            return Err(Error::format(format!(
                "unsupported format version {version}"
            )));
        }
        let suite = &data[10..18];
        if suite
            .iter()
            .take_while(|b| **b != 0)
            .copied()
            .collect::<Vec<_>>()
            != SUITE.as_bytes()
        {
            return Err(Error::format("unsupported crypto suite"));
        }
        let vault_id = Id(data[18..34].try_into().unwrap());
        let mut entries = Vec::new();
        let mut pos = HEADER_LEN;
        while pos < data.len() {
            if data.len() - pos < 4 {
                return Err(Error::format("truncated entry"));
            }
            let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if data.len() - pos < len {
                return Err(Error::format("truncated entry"));
            }
            let bytes = data[pos..pos + len].to_vec();
            pos += len;
            let envelope: Envelope = from_cbor(&bytes)?;
            entries.push(RawEntry { bytes, envelope });
        }
        if entries.is_empty() {
            return Err(Error::format("vault has no checkpoint"));
        }
        Ok(VaultFile { vault_id, entries })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        let mut suite = [0u8; 8];
        suite[..SUITE.len()].copy_from_slice(SUITE.as_bytes());
        out.extend_from_slice(&suite);
        out.extend_from_slice(&self.vault_id.0);
        for e in &self.entries {
            out.extend_from_slice(&(e.bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&e.bytes);
        }
        out
    }

    /// `seq` and logical head hash of the last entry (unverified).
    pub fn logical_head(&self) -> Result<(u64, [u8; 32])> {
        let last = self.entries.last().unwrap();
        if self.entries.len() == 1 {
            let cp: CheckpointBody = from_cbor(&last.envelope.body)?;
            Ok((cp.seq, cp.folded_head.unwrap_or_else(|| last.hash())))
        } else {
            let body: CommitBody = from_cbor(&last.envelope.body)?;
            Ok((body.seq, last.hash()))
        }
    }

    pub fn head_hash(&self) -> [u8; 32] {
        self.entries.last().unwrap().hash()
    }
}

/// Reads only the header of a vault file.
pub fn peek_vault_id(data: &[u8]) -> Result<Id> {
    if data.len() < HEADER_LEN || &data[..8] != MAGIC {
        return Err(Error::format("not a nepomuk vault file"));
    }
    Ok(Id(data[18..34].try_into().unwrap()))
}
