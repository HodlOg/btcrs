use crate::bitcoin::BITCOIN;
use crate::ecdsa::{sign_hash, verify_hash, Signature};
use crate::keys::PublicKey;
use crate::sha256::sha256;
use crate::utils::{decode_int, decode_varint, encode_int, encode_varint};
use num_bigint::BigInt;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub enum ScriptCmd {
    Op(u8),
    Data(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Script {
    pub cmds: Vec<ScriptCmd>,
}

impl Default for Script {
    fn default() -> Self {
        Self::new()
    }
}

impl Script {
    pub fn new() -> Self {
        Script { cmds: Vec::new() }
    }

    pub fn decode<R: Read>(reader: &mut R) -> Self {
        let length = decode_varint(reader).unwrap();
        let mut cmds = Vec::new();

        let mut buf = vec![0u8; length as usize];
        reader.read_exact(&mut buf).unwrap();
        let mut cursor = Cursor::new(buf);

        while cursor.position() < length {
            let mut byte_buf = [0u8; 1];
            cursor.read_exact(&mut byte_buf).unwrap();
            let current = byte_buf[0];

            if (1..=75).contains(&current) {
                let mut data = vec![0u8; current as usize];
                cursor.read_exact(&mut data).unwrap();
                cmds.push(ScriptCmd::Data(data));
            } else if current == 76 {
                // OP_PUSHDATA1
                let len = decode_int(&mut cursor, 1).unwrap();
                let mut data = vec![0u8; len as usize];
                cursor.read_exact(&mut data).unwrap();
                cmds.push(ScriptCmd::Data(data));
            } else if current == 77 {
                // OP_PUSHDATA2
                let len = decode_int(&mut cursor, 2).unwrap();
                let mut data = vec![0u8; len as usize];
                cursor.read_exact(&mut data).unwrap();
                cmds.push(ScriptCmd::Data(data));
            } else {
                cmds.push(ScriptCmd::Op(current));
            }
        }
        Script { cmds }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for cmd in &self.cmds {
            match cmd {
                ScriptCmd::Op(op) => out.push(*op),
                ScriptCmd::Data(data) => {
                    let len = data.len();
                    if len < 75 {
                        out.push(len as u8);
                    } else if len <= 255 {
                        out.push(76); // OP_PUSHDATA1
                        out.push(len as u8);
                    } else if len <= 520 {
                        out.push(77); // OP_PUSHDATA2
                        out.extend(encode_int(len as u64, 2));
                    } else {
                        panic!("Data too long for script");
                    }
                    out.extend(data);
                }
            }
        }
        let mut res = encode_varint(out.len() as u64);
        res.extend(out);
        res
    }

    /// create a P2PKH (Pay to Public Key Hash) scriptPubKey.
    pub fn p2pkh(pubkey_hash: &[u8]) -> Self {
        Script {
            cmds: vec![
                ScriptCmd::Op(118), // OP_DUP
                ScriptCmd::Op(169), // OP_HASH160
                ScriptCmd::Data(pubkey_hash.to_vec()),
                ScriptCmd::Op(136), // OP_EQUALVERIFY
                ScriptCmd::Op(172), // OP_CHECKSIG
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct TxIn {
    pub prev_tx: Vec<u8>,
    pub prev_index: u32,
    pub script_sig: Script,
    pub sequence: u32,
    pub witness: Option<Vec<Vec<u8>>>,
    pub net: String,
}

impl TxIn {
    pub fn decode<R: Read>(reader: &mut R) -> Self {
        let mut prev_tx = vec![0u8; 32];
        reader.read_exact(&mut prev_tx).unwrap();
        prev_tx.reverse();

        let prev_index = decode_int(reader, 4).unwrap() as u32;
        let script_sig = Script::decode(reader);
        let sequence = decode_int(reader, 4).unwrap() as u32;

        TxIn {
            prev_tx,
            prev_index,
            script_sig,
            sequence,
            witness: None,
            net: "main".to_string(),
        }
    }

    pub fn encode(&self, script_override: Option<bool>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev_tx_rev = self.prev_tx.clone();
        prev_tx_rev.reverse();
        out.extend(prev_tx_rev);
        out.extend(encode_int(self.prev_index as u64, 4));

        match script_override {
            None => out.extend(self.script_sig.encode()),
            Some(true) => {
                let tx = TxFetcher::fetch(&hex::encode(&self.prev_tx), &self.net);
                out.extend(tx.tx_outs[self.prev_index as usize].script_pubkey.encode());
            }
            Some(false) => {
                out.extend(Script::new().encode());
            }
        }

        out.extend(encode_int(self.sequence as u64, 4));
        out
    }
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub amount: u64,
    pub script_pubkey: Script,
}

impl TxOut {
    pub fn decode<R: Read>(reader: &mut R) -> Self {
        let amount = decode_int(reader, 8).unwrap();
        let script_pubkey = Script::decode(reader);
        TxOut {
            amount,
            script_pubkey,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(encode_int(self.amount, 8));
        out.extend(self.script_pubkey.encode());
        out
    }
}

#[derive(Debug, Clone)]
pub struct Tx {
    pub version: u32,
    pub tx_ins: Vec<TxIn>,
    pub tx_outs: Vec<TxOut>,
    pub locktime: u32,
    pub segwit: bool,
}

impl Tx {
    pub fn decode<R: Read>(reader: &mut R) -> Self {
        let version = decode_int(reader, 4).unwrap() as u32;

        let mut num_inputs = decode_varint(reader).unwrap();
        let mut segwit = false;

        if num_inputs == 0 {
            let mut flag = [0u8; 1];
            reader.read_exact(&mut flag).unwrap();
            if flag[0] == 1 {
                segwit = true;
                num_inputs = decode_varint(reader).unwrap();
            }
        }

        let mut tx_ins = Vec::new();
        for _ in 0..num_inputs {
            tx_ins.push(TxIn::decode(reader));
        }

        let num_outputs = decode_varint(reader).unwrap();
        let mut tx_outs = Vec::new();
        for _ in 0..num_outputs {
            tx_outs.push(TxOut::decode(reader));
        }

        if segwit {
            for tx_in in &mut tx_ins {
                let num_items = decode_varint(reader).unwrap();
                let mut items = Vec::new();
                for _ in 0..num_items {
                    let item_len = decode_varint(reader).unwrap();
                    if item_len == 0 {
                        items.push(vec![]);
                    } else {
                        let mut item = vec![0u8; item_len as usize];
                        reader.read_exact(&mut item).unwrap();
                        items.push(item);
                    }
                }
                tx_in.witness = Some(items);
            }
        }

        let locktime = decode_int(reader, 4).unwrap() as u32;

        Tx {
            version,
            tx_ins,
            tx_outs,
            locktime,
            segwit,
        }
    }

    pub fn encode(&self, force_legacy: bool, sig_index: Option<usize>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(encode_int(self.version as u64, 4));

        if self.segwit && !force_legacy {
            out.push(0x00); // Marker
            out.push(0x01); // Flag
        }

        out.extend(encode_varint(self.tx_ins.len() as u64));

        for (i, tx_in) in self.tx_ins.iter().enumerate() {
            let override_script = sig_index.map(|idx| idx == i);
            out.extend(tx_in.encode(override_script));
        }

        out.extend(encode_varint(self.tx_outs.len() as u64));
        for tx_out in &self.tx_outs {
            out.extend(tx_out.encode());
        }

        if self.segwit && !force_legacy {
            for tx_in in &self.tx_ins {
                if let Some(witness) = &tx_in.witness {
                    out.extend(encode_varint(witness.len() as u64));
                    for item in witness {
                        out.extend(encode_varint(item.len() as u64));
                        out.extend(item);
                    }
                } else {
                    out.push(0x00);
                }
            }
        }

        out.extend(encode_int(self.locktime as u64, 4));

        if sig_index.is_some() {
            out.extend(encode_int(1, 4)); // SIGHASH_ALL
        }

        out
    }

    /// compute the transaction ID (txid).
    pub fn id(&self) -> String {
        let encoded = self.encode(true, None);
        let hash = sha256(&sha256(&encoded));
        let mut hash_rev = hash;
        hash_rev.reverse();
        hex::encode(hash_rev)
    }

    /// get the txid as raw bytes (big-endian, as used internally).
    pub fn txid_bytes(&self) -> Vec<u8> {
        let encoded = self.encode(true, None);
        let hash = sha256(&sha256(&encoded));
        let mut hash_rev = hash;
        hash_rev.reverse();
        hash_rev
    }

    /// calculate the fee for this transaction (requires fetching previous outputs).
    pub fn fee(&self) -> u64 {
        let input_sum: u64 = self
            .tx_ins
            .iter()
            .map(|input| {
                let prev_tx = TxFetcher::fetch(&hex::encode(&input.prev_tx), &input.net);
                prev_tx.tx_outs[input.prev_index as usize].amount
            })
            .sum();

        let output_sum: u64 = self.tx_outs.iter().map(|o| o.amount).sum();

        input_sum.saturating_sub(output_sum)
    }

    /// compute the signature hash (sighash) for a specific input using SIGHASH_ALL.
    pub fn sig_hash(&self, input_index: usize) -> Vec<u8> {
        // encode with sig_index creates the signing serialization (sighash)
        let preimage = self.encode(true, Some(input_index));
        sha256(&sha256(&preimage))
    }

    /// sign a transaction input with a private key.
    pub fn sign_input(&mut self, input_index: usize, secret_key: &BigInt, compressed: bool) -> bool {
        if input_index >= self.tx_ins.len() {
            return false;
        }

        // compute the sighash
        let z = self.sig_hash(input_index);

        // sign the hash
        let sig = sign_hash(secret_key, &z);

        // encode signature in DER format + SIGHASH_ALL byte
        let mut sig_bytes = sig.encode();
        sig_bytes.push(0x01); // SIGHASH_ALL

        // get the public key
        let pk = PublicKey::from_sk(secret_key, &BITCOIN.generator.g);
        let pk_bytes = pk.encode(compressed, false);

        // build scriptSig: <sig> <pubkey>
        self.tx_ins[input_index].script_sig = Script {
            cmds: vec![ScriptCmd::Data(sig_bytes), ScriptCmd::Data(pk_bytes)],
        };

        true
    }

    /// verify the signature on a transaction input.
    /// this verifies a P2PKH input by:
    /// 1. extracting the signature and public key from scriptSig
    /// 2. verifying that the public key hashes to the expected value in scriptPubKey
    /// 3. computing the sighash
    /// 4. verifying the ECDSA signature
    pub fn verify_input(&self, input_index: usize) -> bool {
        use crate::ripemd160::ripemd160;

        if input_index >= self.tx_ins.len() {
            return false;
        }

        let tx_in = &self.tx_ins[input_index];

        // extract signature and pubkey from scriptSig
        if tx_in.script_sig.cmds.len() < 2 {
            return false;
        }

        let (sig_bytes, pk_bytes) = match (&tx_in.script_sig.cmds[0], &tx_in.script_sig.cmds[1]) {
            (ScriptCmd::Data(sig), ScriptCmd::Data(pk)) => (sig, pk),
            _ => return false,
        };

        // parse the DER signature (strip SIGHASH byte at the end)
        if sig_bytes.is_empty() {
            return false;
        }
        let sig = match Signature::decode(&sig_bytes[..sig_bytes.len() - 1]) {
            Some(s) => s,
            None => return false,
        };

        // parse the public key
        let pk = match PublicKey::decode(pk_bytes) {
            Some(p) => p,
            None => return false,
        };

        // fetch the previous output to get the scriptPubKey
        let prev_tx = TxFetcher::fetch(&hex::encode(&tx_in.prev_tx), &tx_in.net);
        let prev_output = &prev_tx.tx_outs[tx_in.prev_index as usize];

        // for P2PKH, verify that HASH160(pubkey) matches the hash in scriptPubKey
        if prev_output.script_pubkey.cmds.len() >= 3 {
            if let ScriptCmd::Data(expected_hash) = &prev_output.script_pubkey.cmds[2] {
                let actual_hash = ripemd160(&sha256(pk_bytes));
                if actual_hash != *expected_hash {
                    return false; // Public key doesn't match expected hash
                }
            }
        }

        // compute the sighash
        let z = self.sig_hash(input_index);

        // verify the signature
        verify_hash(&pk.point, &z, &sig)
    }
}

pub struct TxFetcher;

lazy_static::lazy_static! {
    static ref TX_CACHE: Mutex<HashMap<String, Vec<u8>>> = Mutex::new(HashMap::new());
}

impl TxFetcher {
    pub fn fetch(tx_id: &str, net: &str) -> Tx {
        let mut cache = TX_CACHE.lock().unwrap();
        if let Some(raw) = cache.get(tx_id) {
            let mut cursor = Cursor::new(raw);
            return Tx::decode(&mut cursor);
        }

        let url = match net {
            "main" => format!("https://blockstream.info/api/tx/{}/hex", tx_id),
            "test" => format!("https://blockstream.info/testnet/api/tx/{}/hex", tx_id),
            _ => panic!("Unknown network"),
        };

        let resp = reqwest::blocking::get(&url)
            .expect("Failed to fetch tx")
            .text()
            .expect("Failed to get text");
        let raw = hex::decode(resp.trim()).expect("Failed to decode hex");

        cache.insert(tx_id.to_string(), raw.clone());

        let mut cursor = Cursor::new(raw);
        Tx::decode(&mut cursor)
    }

    pub fn cache_tx(tx_id: &str, raw: Vec<u8>) {
        let mut cache = TX_CACHE.lock().unwrap();
        cache.insert(tx_id.to_string(), raw);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_legacy_decode() {
        let raw_hex = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let raw = hex::decode(raw_hex).unwrap();
        let mut cursor = Cursor::new(&raw);
        let tx = Tx::decode(&mut cursor);

        assert_eq!(tx.version, 1);
        assert!(!tx.segwit);
        assert_eq!(tx.tx_ins.len(), 1);
        assert_eq!(
            hex::encode(&tx.tx_ins[0].prev_tx),
            "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81"
        );
        assert_eq!(tx.tx_ins[0].prev_index, 0);
        assert_eq!(tx.tx_ins[0].sequence, 0xfffffffe);
        assert!(tx.tx_ins[0].witness.is_none());

        assert_eq!(tx.tx_outs.len(), 2);
        assert_eq!(tx.tx_outs[0].amount, 32454049);
        assert_eq!(tx.tx_outs[1].amount, 10011545);

        assert_eq!(tx.locktime, 410393);
        assert_eq!(
            tx.id(),
            "452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03"
        );

        let encoded = tx.encode(false, None);
        assert_eq!(hex::encode(encoded), raw_hex);
    }

    #[test]
    fn test_segwit_decode() {
        let raw_hex = "010000000001026c4224e4d6bab0cfdfd67870e084cda34e42d3544b3c77d310df40831fa4f5061700000023220020fb24ee0fec024ff3ff03c44d16ca523b78fd33ebaab99176e98b3f5e0e78da9dffffffffe8faf73aee5a09b1b678277fc63150dff639c97521e9088d6721a2b995f33664010000002322002083e1adc1eb82945fa99500bcd9df963b0e731524fd8eb25ef205e88d3bd7ab77ffffffff03a0370a00000000001976a914b00ff32bbc990acde3e5ac022e6d4120fb168f1e88ac7f791300000000001976a914128afed7e8d4e6f3a9d2d38ad560c307ebf392ba88ac54115c00000000001976a914c65d16caa1d8c1c46cc1bfac92eff06b02d8afcc88ac04004830450221009d93dc766b4a3417d7daccffe39719cd0344779c19d589d3a078625139a7dcd50220267c1b9b365d0eaa3b036771cbfc994c2b1c5b29e5107f023f036360cb60c8b50147304402206346b5c2bfa243c9cd0c5056abedfadc79e4a2b67b918315fc3faf79dfd12d7602203f729a665afd02ceb4b07898c06c81f0dfc378f66409ed828a4b5fe84f9287550169522102b951c91d97118489d1980ec472d89b5bc98fb98d0bafa17aca238d18a758b8642103d45b78e2a683330c62878e44610a5d1c8d40bd1f261b1110940b1b8a5aecd3e82103796ecd1667be6e20af571c46517e4ecf5e83052df864266658dd7f88e63efa6153ae0400483045022100e396deff2fe6dd6081e35f9dced6e09ea1b8b4830ae322b5d58986596996893d0220485420653c118c1a13b48941166b242077530d2b3cab908abe67af6b96ef2850014730440220171e11f4d6a106464a94e29f46750803a7deb214e6fbe2140ec5d80577dded0e02203483ab0c685f66e17b4afa86ba053732b43ff1ca7654796e72b69bd224bf26c4016952210375e42f77749f92a6b54c8e85fab2209e6807e15a3768c024a5cab01dc301c0282103fd4969521bd2d0f8e147c16655ae9c29dc48cb4f124b7a6398db78b1cbc878a221036bc18f387d1e4ba80492854cee639bd4ab6e3a310d9faa6f17350bbdc4c029d053ae25680a00";
        let raw = hex::decode(raw_hex).unwrap();
        let mut cursor = Cursor::new(&raw);
        let tx = Tx::decode(&mut cursor);

        assert_eq!(tx.version, 1);
        assert!(tx.segwit);
        assert_eq!(tx.tx_ins.len(), 2);
        assert!(tx.tx_ins[0].witness.is_some());
        assert!(tx.tx_ins[1].witness.is_some());

        assert_eq!(tx.tx_outs.len(), 3);
        assert_eq!(tx.tx_outs[0].amount, 669600);
        assert_eq!(tx.tx_outs[1].amount, 1276287);
        assert_eq!(tx.tx_outs[2].amount, 6033748);

        assert_eq!(
            tx.id(),
            "3ecf9b3d965cfaa2c472f09b5f487fbd838e4e1f861e3542c541d39c5cb7bc25"
        );

        let encoded = tx.encode(false, None);
        assert_eq!(hex::encode(encoded), raw_hex);
    }

    #[test]
    fn test_script_default() {
        let script = Script::default();
        assert!(script.cmds.is_empty());
    }

    #[test]
    fn test_p2pkh_script() {
        let pubkey_hash = vec![0xab; 20];
        let script = Script::p2pkh(&pubkey_hash);

        assert_eq!(script.cmds.len(), 5);
        assert_eq!(script.cmds[0], ScriptCmd::Op(118)); // OP_DUP
        assert_eq!(script.cmds[1], ScriptCmd::Op(169)); // OP_HASH160
        assert_eq!(script.cmds[2], ScriptCmd::Data(pubkey_hash));
        assert_eq!(script.cmds[3], ScriptCmd::Op(136)); // OP_EQUALVERIFY
        assert_eq!(script.cmds[4], ScriptCmd::Op(172)); // OP_CHECKSIG
    }

    #[test]
    fn test_create_tx() {
        let prev_tx_hex = "0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299";
        let prev_tx = hex::decode(prev_tx_hex).unwrap();
        let prev_index = 13;
        let tx_in = TxIn {
            prev_tx,
            prev_index,
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: None,
            net: "test".to_string(),
        };

        // change output using helper
        let amount_change = (0.33 * 1e8) as u64;
        let pkb_hash_change = hex::decode("d1d80577dded0e02203483ab0c685f66e17b4afa").unwrap();
        let tx_out_change = TxOut {
            amount: amount_change,
            script_pubkey: Script::p2pkh(&pkb_hash_change),
        };

        let amount_target = (0.1 * 1e8) as u64;
        let pkb_hash_target = hex::decode("7a986d955c6e0cb35d446a89d3f56100f4d7f678").unwrap();
        let tx_out_target = TxOut {
            amount: amount_target,
            script_pubkey: Script::p2pkh(&pkb_hash_target),
        };

        let tx = Tx {
            version: 1,
            tx_ins: vec![tx_in],
            tx_outs: vec![tx_out_change, tx_out_target],
            locktime: 0,
            segwit: false,
        };

        assert_eq!(tx.tx_ins.len(), 1);
        assert_eq!(tx.tx_outs.len(), 2);
    }

    fn fake_coinbase_input() -> TxIn {
        TxIn {
            prev_tx: vec![0u8; 32], // Null txid for coinbase
            prev_index: 0xffffffff,
            script_sig: Script {
                cmds: vec![ScriptCmd::Data(vec![0x04, 0xff, 0xff, 0x00, 0x1d])], // Fake coinbase data
            },
            sequence: 0xffffffff,
            witness: None,
            net: "main".to_string(),
        }
    }

    #[test]
    fn test_sign_and_verify_input() {
        use crate::keys::PublicKey;
        use num_traits::Num;

        let secret_key = BigInt::from_str_radix(
            "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD",
            16,
        )
        .unwrap();

        // create the public key and get its hash for P2PKH
        let pk = PublicKey::from_sk(&secret_key, &crate::bitcoin::BITCOIN.generator.g);
        let pkb_hash = pk.encode(true, true); // compressed, hash160

        // create a fake previous transaction that pays to our public key
        let prev_tx_out = TxOut {
            amount: 100_000_000, // 1 BTC
            script_pubkey: Script::p2pkh(&pkb_hash),
        };

        let fake_prev_tx = Tx {
            version: 1,
            tx_ins: vec![fake_coinbase_input()],
            tx_outs: vec![prev_tx_out],
            locktime: 0,
            segwit: false,
        };

        let prev_txid = fake_prev_tx.txid_bytes();
        TxFetcher::cache_tx(&hex::encode(&prev_txid), fake_prev_tx.encode(false, None));

        let tx_in = TxIn {
            prev_tx: prev_txid,
            prev_index: 0,
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: None,
            net: "main".to_string(),
        };

        // create an output (sending to some address)
        let target_pkb_hash = hex::decode("7a986d955c6e0cb35d446a89d3f56100f4d7f678").unwrap();
        let tx_out = TxOut {
            amount: 99_990_000, // 0.9999 BTC (0.0001 BTC fee)
            script_pubkey: Script::p2pkh(&target_pkb_hash),
        };

        let mut tx = Tx {
            version: 1,
            tx_ins: vec![tx_in],
            tx_outs: vec![tx_out],
            locktime: 0,
            segwit: false,
        };

        let signed = tx.sign_input(0, &secret_key, true);
        assert!(signed, "Signing should succeed");

        assert_eq!(tx.tx_ins[0].script_sig.cmds.len(), 2);

        let valid = tx.verify_input(0);
        assert!(valid, "Signature verification should succeed");
    }

    #[test]
    fn test_sign_input_invalid_index() {
        let mut tx = Tx {
            version: 1,
            tx_ins: vec![],
            tx_outs: vec![],
            locktime: 0,
            segwit: false,
        };

        let secret_key = BigInt::from(12345);
        assert!(!tx.sign_input(0, &secret_key, true));
        assert!(!tx.sign_input(99, &secret_key, true));
    }

    #[test]
    fn test_verify_input_invalid_index() {
        let tx = Tx {
            version: 1,
            tx_ins: vec![],
            tx_outs: vec![],
            locktime: 0,
            segwit: false,
        };

        assert!(!tx.verify_input(0));
        assert!(!tx.verify_input(99));
    }

    #[test]
    fn test_verify_wrong_signature() {
        use crate::keys::PublicKey;
        use num_traits::Num;

        let secret_key1 = BigInt::from_str_radix(
            "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD",
            16,
        )
        .unwrap();
        let secret_key2 = BigInt::from(999999);

        let pk1 = PublicKey::from_sk(&secret_key1, &crate::bitcoin::BITCOIN.generator.g);
        let pkb_hash1 = pk1.encode(true, true);

        let prev_tx_out = TxOut {
            amount: 100_000_000,
            script_pubkey: Script::p2pkh(&pkb_hash1),
        };

        let fake_prev_tx = Tx {
            version: 1,
            tx_ins: vec![fake_coinbase_input()],
            tx_outs: vec![prev_tx_out],
            locktime: 0,
            segwit: false,
        };

        let prev_txid = fake_prev_tx.txid_bytes();
        TxFetcher::cache_tx(&hex::encode(&prev_txid), fake_prev_tx.encode(false, None));

        let tx_in = TxIn {
            prev_tx: prev_txid,
            prev_index: 0,
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: None,
            net: "main".to_string(),
        };

        let tx_out = TxOut {
            amount: 99_990_000,
            script_pubkey: Script::p2pkh(&[0u8; 20]),
        };

        let mut tx = Tx {
            version: 1,
            tx_ins: vec![tx_in],
            tx_outs: vec![tx_out],
            locktime: 0,
            segwit: false,
        };

        tx.sign_input(0, &secret_key2, true);
        assert!(!tx.verify_input(0), "Verification should fail with wrong key");
    }

    #[test]
    fn test_sig_hash_deterministic() {
        let prev_tx_out = TxOut {
            amount: 100_000_000,
            script_pubkey: Script::p2pkh(&[0xab; 20]),
        };

        let fake_prev_tx = Tx {
            version: 1,
            tx_ins: vec![fake_coinbase_input()],
            tx_outs: vec![prev_tx_out],
            locktime: 0,
            segwit: false,
        };

        let prev_txid = fake_prev_tx.txid_bytes();
        TxFetcher::cache_tx(&hex::encode(&prev_txid), fake_prev_tx.encode(false, None));

        let tx_in = TxIn {
            prev_tx: prev_txid,
            prev_index: 0,
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: None,
            net: "main".to_string(),
        };

        let tx_out = TxOut {
            amount: 50_000_000,
            script_pubkey: Script::p2pkh(&[0u8; 20]),
        };

        let tx = Tx {
            version: 1,
            tx_ins: vec![tx_in],
            tx_outs: vec![tx_out],
            locktime: 0,
            segwit: false,
        };

        // Sighash should be deterministic
        let hash1 = tx.sig_hash(0);
        let hash2 = tx.sig_hash(0);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_pubkey_encode_decode_roundtrip() {
        use crate::keys::PublicKey;
        use num_traits::Num;

        let secret_key = BigInt::from_str_radix(
            "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD",
            16,
        )
        .unwrap();

        let pk = PublicKey::from_sk(&secret_key, &crate::bitcoin::BITCOIN.generator.g);

        let compressed = pk.encode(true, false);
        let decoded_compressed = PublicKey::decode(&compressed).unwrap();
        assert_eq!(pk.point, decoded_compressed.point);
        let uncompressed = pk.encode(false, false);
        let decoded_uncompressed = PublicKey::decode(&uncompressed).unwrap();
        assert_eq!(pk.point, decoded_uncompressed.point);
    }
}
