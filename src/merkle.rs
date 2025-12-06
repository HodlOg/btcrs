//! Merkle tree implementation for Bitcoin.

use crate::sha256::sha256;

/// Compute the Merkle root from a list of transaction IDs.
pub fn merkle_root(txids: &[Vec<u8>]) -> Vec<u8> {
    if txids.is_empty() {
        // Empty block edge case (shouldn't happen in practice, coinbase is always present)
        return vec![0u8; 32];
    }

    if txids.len() == 1 {
        return txids[0].clone();
    }

    // Copy txids to working layer
    let mut current_layer: Vec<Vec<u8>> = txids.to_vec();

    while current_layer.len() > 1 {
        // If odd, duplicate last element
        if current_layer.len() % 2 == 1 {
            current_layer.push(current_layer.last().unwrap().clone());
        }

        let mut next_layer = Vec::with_capacity(current_layer.len() / 2);

        for pair in current_layer.chunks(2) {
            let combined = merkle_parent(&pair[0], &pair[1]);
            next_layer.push(combined);
        }

        current_layer = next_layer;
    }

    current_layer.pop().unwrap()
}

/// compute the parent hash of two merkle tree nodes
fn merkle_parent(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(left);
    combined.extend_from_slice(right);
    sha256(&sha256(&combined))
}

/// a merkle proof for transaction inclusion
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// being proven
    pub txid: Vec<u8>,
    /// index of transaction in the block
    pub index: usize,
    /// proof path: (hash, is_left) pairs
    pub path: Vec<(Vec<u8>, bool)>,
}

impl MerkleProof {
    pub fn generate(txids: &[Vec<u8>], index: usize) -> Option<Self> {
        if txids.is_empty() || index >= txids.len() {
            return None;
        }

        let txid = txids[index].clone();
        let mut path = Vec::new();
        let mut current_layer: Vec<Vec<u8>> = txids.to_vec();
        let mut current_index = index;

        while current_layer.len() > 1 {
            // if odd, duplicate last element
            if current_layer.len() % 2 == 1 {
                current_layer.push(current_layer.last().unwrap().clone());
            }

            // find sibling
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            // is_left means sibling is on the left of current node
            let is_left = !current_index.is_multiple_of(2);
            path.push((current_layer[sibling_index].clone(), is_left));

            // build next layer
            let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
            for pair in current_layer.chunks(2) {
                let combined = merkle_parent(&pair[0], &pair[1]);
                next_layer.push(combined);
            }

            current_layer = next_layer;
            current_index /= 2;
        }

        Some(MerkleProof { txid, index, path })
    }

    pub fn verify(&self, expected_root: &[u8]) -> bool {
        let mut current = self.txid.clone();

        for (sibling, is_left) in &self.path {
            if *is_left {
                current = merkle_parent(sibling, &current);
            } else {
                current = merkle_parent(&current, sibling);
            }
        }

        current == expected_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_txid(n: u8) -> Vec<u8> {
        // create a simple mock txid for testing
        let mut txid = vec![0u8; 32];
        txid[0] = n;
        txid
    }

    #[test]
    fn test_merkle_root_single() {
        let txids = vec![mock_txid(1)];
        let root = merkle_root(&txids);
        assert_eq!(root, txids[0]);
    }

    #[test]
    fn test_merkle_root_two() {
        let txids = vec![mock_txid(1), mock_txid(2)];
        let root = merkle_root(&txids);
        let expected = merkle_parent(&txids[0], &txids[1]);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_odd() {
        // with 3 txids, the third should be duplicated
        let txids = vec![mock_txid(1), mock_txid(2), mock_txid(3)];
        let root = merkle_root(&txids);

        // manual computation
        let h01 = merkle_parent(&txids[0], &txids[1]);
        let h23 = merkle_parent(&txids[2], &txids[2]); // Duplicate last
        let expected = merkle_parent(&h01, &h23);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_four() {
        let txids = vec![mock_txid(1), mock_txid(2), mock_txid(3), mock_txid(4)];
        let root = merkle_root(&txids);

        // manual computation
        let h01 = merkle_parent(&txids[0], &txids[1]);
        let h23 = merkle_parent(&txids[2], &txids[3]);
        let expected = merkle_parent(&h01, &h23);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_proof_generation_and_verification() {
        let txids: Vec<Vec<u8>> = (0..8).map(mock_txid).collect();
        let root = merkle_root(&txids);

        // test proof for each transaction
        for i in 0..txids.len() {
            let proof = MerkleProof::generate(&txids, i).unwrap();
            assert_eq!(proof.txid, txids[i]);
            assert_eq!(proof.index, i);
            assert!(proof.verify(&root), "Proof failed for index {}", i);
        }
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let txids: Vec<Vec<u8>> = (0..4).map(mock_txid).collect();
        let root = merkle_root(&txids);

        // create a proof and tamper with the txid
        let mut proof = MerkleProof::generate(&txids, 1).unwrap();
        proof.txid[0] ^= 0xff; // Flip some bits

        assert!(!proof.verify(&root));
    }

    #[test]
    fn test_known_merkle_root() {
        let txids = vec![
            hex::decode("c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5")
                .unwrap(),
            hex::decode("c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5")
                .unwrap(),
        ];

        let root = merkle_root(&txids);

        // expected root for these two txids (computed by hashing them together)
        let expected = merkle_parent(&txids[0], &txids[1]);
        assert_eq!(root, expected);
    }
}
