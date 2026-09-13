//! Long-message RBC coding (Simple-IT §2.4). No protocol votes are signed here.

use super::{Error, Params};
use crypto_primitives::{
    hash::hash_len_prefixed,
    merkle::{MerkleProof, MerkleTree},
};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const NODE_DOMAIN: &[u8] = b"silk/simple-it/rs-merkle-node/v1";
const MAX_PAYLOAD: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Fragment {
    pub root: [u8; 32],
    pub payload_len: u32,
    pub index: u32,
    pub shard: Vec<u8>,
    pub proof: MerkleProof,
}

fn shard_len(params: Params, payload_len: usize) -> Result<usize, Error> {
    if payload_len == 0 || payload_len > MAX_PAYLOAD {
        return Err(Error::InvalidPayload);
    }
    Ok(payload_len.div_ceil(params.data_shards()).div_ceil(64) * 64)
}

fn leaf(context: &[u8; 32], round: u64, length: u32, index: usize, shard: &[u8]) -> [u8; 32] {
    hash_len_prefixed(
        b"silk/simple-it/rs-leaf/v1",
        &[
            context,
            &round.to_le_bytes(),
            &length.to_le_bytes(),
            &(index as u32).to_le_bytes(),
            shard,
        ],
    )
}

fn codeword(params: Params, payload: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let k = params.data_shards();
    let size = shard_len(params, payload.len())?;
    let mut shards = vec![vec![0; size]; k];
    for (dest, source) in shards.iter_mut().zip(payload.chunks(size)) {
        dest[..source.len()].copy_from_slice(source);
    }
    if k == params.n {
        return Ok(shards);
    }
    let mut encoder = ReedSolomonEncoder::new(k, params.n - k, size).map_err(|_| Error::Coding)?;
    for shard in &shards {
        encoder
            .add_original_shard(shard)
            .map_err(|_| Error::Coding)?;
    }
    let result = encoder.encode().map_err(|_| Error::Coding)?;
    shards.extend(result.recovery_iter().map(<[u8]>::to_vec));
    Ok(shards)
}

fn tree(
    params: Params,
    context: &[u8; 32],
    round: u64,
    length: u32,
    shards: &[Vec<u8>],
) -> Result<MerkleTree, Error> {
    if shards.len() != params.n {
        return Err(Error::InvalidPayload);
    }
    MerkleTree::new(
        NODE_DOMAIN,
        shards
            .iter()
            .enumerate()
            .map(|(i, shard)| leaf(context, round, length, i, shard))
            .collect(),
    )
    .map_err(|_| Error::InvalidPayload)
}

pub fn disperse(
    params: Params,
    context: &[u8; 32],
    round: u64,
    payload: &[u8],
) -> Result<Vec<Fragment>, Error> {
    let shards = codeword(params, payload)?;
    let tree = tree(params, context, round, payload.len() as u32, &shards)?;
    shards
        .into_iter()
        .enumerate()
        .map(|(i, shard)| {
            Ok(Fragment {
                root: tree.root(),
                payload_len: payload.len() as u32,
                index: i as u32,
                shard,
                proof: tree.proof(i).map_err(|_| Error::InvalidPayload)?,
            })
        })
        .collect()
}

pub fn verify_fragment(
    params: Params,
    context: &[u8; 32],
    round: u64,
    fragment: &Fragment,
) -> bool {
    let index = fragment.index as usize;
    let Ok(size) = shard_len(params, fragment.payload_len as usize) else {
        return false;
    };
    if index >= params.n
        || fragment.shard.len() != size
        || fragment.proof.index != index
        || fragment.proof.leaf_count != params.n
    {
        return false;
    }
    // MerkleProof::verify alone does not enforce path shape. Enforce the exact
    // index-derived path, including odd-width duplicated rightmost leaves.
    let mut width = params.n;
    let mut cursor = index;
    let mut depth = 0;
    while width > 1 {
        let Some(sibling) = fragment.proof.siblings.get(depth) else {
            return false;
        };
        if sibling.is_left != (cursor % 2 == 1) {
            return false;
        }
        cursor /= 2;
        width = width.div_ceil(2);
        depth += 1;
    }
    fragment.proof.siblings.len() == depth
        && fragment.proof.verify(
            NODE_DOMAIN,
            &fragment.root,
            &leaf(context, round, fragment.payload_len, index, &fragment.shard),
        )
}

pub fn recover(
    params: Params,
    context: &[u8; 32],
    round: u64,
    root: [u8; 32],
    payload_len: u32,
    fragments: &BTreeMap<usize, Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let k = params.data_shards();
    let size = shard_len(params, payload_len as usize)?;
    if fragments.len() < k
        || fragments
            .iter()
            .any(|(i, bytes)| *i >= params.n || bytes.len() != size)
    {
        return Err(Error::InvalidPayload);
    }
    let mut originals = vec![None; k];
    if params.n == k {
        for (i, shard) in fragments {
            originals[*i] = Some(shard.clone());
        }
    } else {
        let mut decoder =
            ReedSolomonDecoder::new(k, params.n - k, size).map_err(|_| Error::Coding)?;
        for (index, shard) in fragments {
            if *index < k {
                decoder
                    .add_original_shard(*index, shard)
                    .map_err(|_| Error::Coding)?;
                originals[*index] = Some(shard.clone());
            } else {
                decoder
                    .add_recovery_shard(*index - k, shard)
                    .map_err(|_| Error::Coding)?;
            }
        }
        let result = decoder.decode().map_err(|_| Error::Coding)?;
        for (index, shard) in result.restored_original_iter() {
            originals[index] = Some(shard.to_vec());
        }
    }
    let mut payload = Vec::with_capacity(k * size);
    for original in originals {
        payload.extend(original.ok_or(Error::Coding)?);
    }
    if payload[payload_len as usize..].iter().any(|b| *b != 0) {
        return Err(Error::InvalidPayload);
    }
    payload.truncate(payload_len as usize);
    // A Merkle-authenticated vector can still be a non-codeword. Re-encode
    // ALL n shards and compare the root before accepting the reconstructed data.
    let shards = codeword(params, &payload)?;
    if tree(params, context, round, payload_len, &shards)?.root() != root {
        return Err(Error::InvalidPayload);
    }
    Ok(payload)
}
