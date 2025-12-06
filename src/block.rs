//! Bitcoin block header parsing and validation.

use crate::merkle::merkle_root;
use crate::sha256::sha256;
use crate::utils::{decode_int, encode_int};
use num_bigint::BigInt;
use num_traits::Num;
use std::io::Read;

/// the target is encoded as: coefficient * 256^(exponent-3)
/// where bits = [coeff_byte0, coeff_byte1, coeff_byte2, exponent]
pub fn bits_to_target(bits: &[u8]) -> BigInt {
    let exponent = bits[3];
    let coeff = BigInt::from_bytes_le(num_bigint::Sign::Plus, &bits[0..3]);
    let base = BigInt::from(256);

    if exponent >= 3 {
        coeff * base.pow((exponent - 3) as u32)
    } else {
        coeff / base.pow((3 - exponent) as u32)
    }
}

pub fn target_to_bits(target: &BigInt) -> Vec<u8> {
    let b = target.to_bytes_be().1;

    if b.is_empty() {
        return vec![0, 0, 0, 0];
    }

    let mut exponent = b.len();
    let mut coeff = Vec::new();

    if b[0] >= 128 {
        // leading bit is 1, negative
        exponent += 1;
        coeff.push(0x00);
        coeff.extend_from_slice(&b[0..std::cmp::min(2, b.len())]);
    } else {
        coeff.extend_from_slice(&b[0..std::cmp::min(3, b.len())]);
    }

    // pad to 3 b
    while coeff.len() < 3 {
        coeff.push(0);
    }

    let mut new_bits = coeff;
    new_bits.reverse();
    new_bits.push(exponent as u8);
    new_bits
}

/// (80 bytes)
#[derive(Debug, Clone)]
pub struct Block {
    pub version: u32,
    pub prev_block: Vec<u8>,
    pub merkle_root: Vec<u8>,
    pub timestamp: u32,
    pub bits: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl Block {
    pub fn decode<R: Read>(reader: &mut R) -> Self {
        let version = decode_int(reader, 4).unwrap() as u32;
        let mut prev_block = vec![0u8; 32];
        reader.read_exact(&mut prev_block).unwrap();
        prev_block.reverse();

        let mut merkle_root = vec![0u8; 32];
        reader.read_exact(&mut merkle_root).unwrap();
        merkle_root.reverse();

        let timestamp = decode_int(reader, 4).unwrap() as u32;
        let mut bits = vec![0u8; 4];
        reader.read_exact(&mut bits).unwrap();

        let mut nonce = vec![0u8; 4];
        reader.read_exact(&mut nonce).unwrap();

        Block {
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);
        out.extend(encode_int(self.version as u64, 4));

        let mut prev_block_rev = self.prev_block.clone();
        prev_block_rev.reverse();
        out.extend(prev_block_rev);

        let mut merkle_root_rev = self.merkle_root.clone();
        merkle_root_rev.reverse();
        out.extend(merkle_root_rev);

        out.extend(encode_int(self.timestamp as u64, 4));
        out.extend(&self.bits);
        out.extend(&self.nonce);
        out
    }

    /// compute the block ID (hash)
    /// the block ID is the double SHA256 of the header, in reverse byte order
    pub fn id(&self) -> String {
        let encoded = self.encode();
        let hash = sha256(&sha256(&encoded));
        let mut hash_rev = hash;
        hash_rev.reverse();
        hex::encode(hash_rev)
    }

    /// get the target value from the bits field
    pub fn target(&self) -> BigInt {
        bits_to_target(&self.bits)
    }

    /// calculate the difficulty relative to the genesis block target
    pub fn difficulty(&self) -> f64 {
        let genesis_target_hex = "00000000FFFF0000000000000000000000000000000000000000000000000000";
        let genesis_target = BigInt::from_str_radix(genesis_target_hex, 16).unwrap();
        let target = self.target();

        // convert to f64 for division
        let genesis_f = genesis_target.to_string().parse::<f64>().unwrap();
        let target_f = target.to_string().parse::<f64>().unwrap();
        genesis_f / target_f
    }

    pub fn validate_pow(&self) -> bool {
        let id_hex = self.id();
        let id_val = BigInt::from_str_radix(&id_hex, 16).unwrap();
        let target = self.target();
        id_val < target
    }

    pub fn validate_merkle_root(&self, txids: &[Vec<u8>]) -> bool {
        if txids.is_empty() {
            return false;
        }

        // compute merkle root from txids
        // txids are stored internally as big-endian, but merkle tree uses little-endian (natural byte order), so we need to reverse them
        let txids_le: Vec<Vec<u8>> = txids
            .iter()
            .map(|txid| {
                let mut le = txid.clone();
                le.reverse();
                le
            })
            .collect();

        let computed_root = merkle_root(&txids_le);

        let mut computed_root_be = computed_root;
        computed_root_be.reverse();

        self.merkle_root == computed_root_be
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_block() {
        // block 100000 from the real blockchain
        let raw_hex = "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200000000006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d4c86041b0f2b5710";
        let raw = hex::decode(raw_hex).unwrap();
        let mut cursor = Cursor::new(&raw);
        let block = Block::decode(&mut cursor);

        assert_eq!(block.version, 1);
        assert_eq!(
            hex::encode(&block.prev_block),
            "000000000002d01c1fccc21636b607dfd930d31d01c3a62104612a1719011250"
        );

        assert_eq!(block.timestamp, 1293623863);
        assert_eq!(hex::encode(&block.bits), "4c86041b");
        assert_eq!(hex::encode(&block.nonce), "0f2b5710");

        assert_eq!(
            block.id(),
            "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
        );

        assert!(block.validate_pow());

        let encoded = block.encode();
        assert_eq!(hex::encode(encoded), raw_hex);
    }

    #[test]
    fn test_bits_to_target_roundtrip() {
        let bits = vec![0x4c, 0x86, 0x04, 0x1b];
        let target = bits_to_target(&bits);
        let bits_back = target_to_bits(&target);
        assert_eq!(bits, bits_back);
    }

    #[test]
    fn test_merkle_root_validation() {
        // create a mock block and txids
        let txid1 = vec![1u8; 32];
        let txid2 = vec![2u8; 32];
        let txids = vec![txid1.clone(), txid2.clone()];

        // compute the expected merkle root
        let txids_le: Vec<Vec<u8>> = txids
            .iter()
            .map(|t| {
                let mut le = t.clone();
                le.reverse();
                le
            })
            .collect();
        let computed = crate::merkle::merkle_root(&txids_le);
        let mut merkle_root_be = computed;
        merkle_root_be.reverse();

        // create block with correct merkle root
        let block = Block {
            version: 1,
            prev_block: vec![0u8; 32],
            merkle_root: merkle_root_be.clone(),
            timestamp: 0,
            bits: vec![0xff, 0xff, 0x00, 0x1d],
            nonce: vec![0; 4],
        };

        assert!(block.validate_merkle_root(&txids));

        // wrong txids should fail
        let wrong_txids = vec![vec![3u8; 32]];
        assert!(!block.validate_merkle_root(&wrong_txids));
    }
}
