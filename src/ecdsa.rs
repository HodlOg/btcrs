//! rfc 6979 deterministic nonce generation prevents nonce reuse attacks
//! bip 62 low-s normalization prevents malleability

use crate::bitcoin::BITCOIN;
use crate::curves::{inv, Point};
use crate::keys::PublicKey;
use crate::sha256::sha256;
use hmac::{Hmac, Mac};
use num_bigint::{BigInt, Sign};
use num_traits::One;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

impl Signature {
    /// in der format
    pub fn encode(&self) -> Vec<u8> {
        fn dern(n: &BigInt) -> Vec<u8> {
            let nb = n.to_bytes_be().1;
            let mut res = Vec::new();
            if nb.first().map(|&b| b >= 0x80).unwrap_or(false) {
                res.push(0x00);
            }
            res.extend(nb);
            res
        }

        let rb = dern(&self.r);
        let sb = dern(&self.s);

        let mut content = Vec::new();
        content.push(0x02);
        content.push(rb.len() as u8);
        content.extend(rb);
        content.push(0x02);
        content.push(sb.len() as u8);
        content.extend(sb);

        let mut frame = Vec::new();
        frame.push(0x30);
        frame.push(content.len() as u8);
        frame.extend(content);
        frame
    }

    /// decode a der-encoded signature
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        // check sequence tag
        if data[0] != 0x30 {
            return None;
        }

        let total_len = data[1] as usize;
        if data.len() < 2 + total_len {
            return None;
        }

        let mut pos = 2;

        // parse r
        if data[pos] != 0x02 {
            return None;
        }
        pos += 1;

        let r_len = data[pos] as usize;
        pos += 1;

        if pos + r_len > data.len() {
            return None;
        }
        let r_bytes = &data[pos..pos + r_len];
        let r = BigInt::from_bytes_be(Sign::Plus, r_bytes);
        pos += r_len;

        // parse s
        if pos >= data.len() || data[pos] != 0x02 {
            return None;
        }
        pos += 1;

        if pos >= data.len() {
            return None;
        }
        let s_len = data[pos] as usize;
        pos += 1;

        if pos + s_len > data.len() {
            return None;
        }
        let s_bytes = &data[pos..pos + s_len];
        let s = BigInt::from_bytes_be(Sign::Plus, s_bytes);

        Some(Signature { r, s })
    }
}

/// rdeterministic nonce generation, adapted from pseudocode
fn generate_k_rfc6979(private_key: &BigInt, message_hash: &[u8], n: &BigInt) -> BigInt {
    let x_bytes = bigint_to_32_bytes(private_key);

    let mut h1 = [0u8; 32];
    let len = message_hash.len().min(32);
    h1[32 - len..].copy_from_slice(&message_hash[..len]);

    // step a-b: initialize v and k
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];

    // step d: k = hmac_k(v || 0x00 || x || h1)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key error");
    mac.update(&v);
    mac.update(&[0x00]);
    mac.update(&x_bytes);
    mac.update(&h1);
    k.copy_from_slice(&mac.finalize().into_bytes());

    // step e: v = hmac_k(v)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key error");
    mac.update(&v);
    v.copy_from_slice(&mac.finalize().into_bytes());

    // step f: k = hmac_k(v || 0x01 || x || h1)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key error");
    mac.update(&v);
    mac.update(&[0x01]);
    mac.update(&x_bytes);
    mac.update(&h1);
    k.copy_from_slice(&mac.finalize().into_bytes());

    // step g: v = hmac_k(v)
    let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key error");
    mac.update(&v);
    v.copy_from_slice(&mac.finalize().into_bytes());

    // step h: generate k
    loop {
        // v = hmac_k(v)
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key error");
        mac.update(&v);
        v.copy_from_slice(&mac.finalize().into_bytes());

        let candidate = BigInt::from_bytes_be(Sign::Plus, &v);

        // check if candidate is in [1, n-1]
        if candidate >= BigInt::one() && candidate < *n {
            return candidate;
        }

        // if not valid, update k and v
        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key error");
        mac.update(&v);
        mac.update(&[0x00]);
        k.copy_from_slice(&mac.finalize().into_bytes());

        let mut mac = HmacSha256::new_from_slice(&k).expect("HMAC key error");
        mac.update(&v);
        v.copy_from_slice(&mac.finalize().into_bytes());
    }
}

/// convert a bigint to a 32-byte big-endian array, padding with zeros if needed
fn bigint_to_32_bytes(n: &BigInt) -> [u8; 32] {
    let bytes = n.to_bytes_be().1;
    let mut result = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    let copy_len = bytes.len().min(32);
    result[start..start + copy_len].copy_from_slice(&bytes[bytes.len() - copy_len..]);
    result
}

/// sign a message using ecdsa with rfc 6979 deterministic nonces
pub fn sign(secret_key: &BigInt, message: &[u8]) -> Signature {
    let n = &BITCOIN.generator.n;
    let z_bytes = sha256(&sha256(message));
    let z = BigInt::from_bytes_be(Sign::Plus, &z_bytes);

    // deterministic k
    let k = generate_k_rfc6979(secret_key, &z_bytes, n);
    let p = PublicKey::from_sk(&k, &BITCOIN.generator.g);

    let r = match p.point {
        Point::Coordinate { x, .. } => x % n,
        Point::Infinity => panic!("k generated point at infinity"),
    };

    let k_inv = inv(&k, n);
    let mut s = (k_inv * (&z + secret_key * &r)) % n;

    // normalize to low s (bip 62)
    let half_n = n / 2;
    if s > half_n {
        s = n - s;
    }

    Signature { r, s }
}

/// verify an ecdsa signature against a public key and message
pub fn verify(public_key: &Point, message: &[u8], sig: &Signature) -> bool {
    let z_bytes = sha256(&sha256(message));
    verify_hash(public_key, &z_bytes, sig)
}

/// sign a pre-computed hash (32 bytes) using ecdsa with rfc 6979
pub fn sign_hash(secret_key: &BigInt, z_bytes: &[u8]) -> Signature {
    let n = &BITCOIN.generator.n;
    let z = BigInt::from_bytes_be(Sign::Plus, z_bytes);

    // deterministic k
    let k = generate_k_rfc6979(secret_key, z_bytes, n);
    let p = PublicKey::from_sk(&k, &BITCOIN.generator.g);

    let r = match p.point {
        Point::Coordinate { x, .. } => x % n,
        Point::Infinity => panic!("k generated point at infinity"),
    };

    let k_inv = inv(&k, n);
    let mut s = (k_inv * (&z + secret_key * &r)) % n;

    let half_n = n / 2;
    if s > half_n {
        s = n - s;
    }

    Signature { r, s }
}

/// verify an ecdsa signature against a public key and pre computed hash
pub fn verify_hash(public_key: &Point, z_bytes: &[u8], sig: &Signature) -> bool {
    let n = &BITCOIN.generator.n;

    if sig.r < BigInt::one() || sig.r >= *n || sig.s < BigInt::one() || sig.s >= *n {
        return false;
    }

    let z = BigInt::from_bytes_be(Sign::Plus, z_bytes);

    let w = inv(&sig.s, n);
    let u1 = (&z * &w) % n;
    let u2 = (&sig.r * &w) % n;

    let p = (&BITCOIN.generator.g * &u1) + (public_key * &u2);

    match p {
        Point::Coordinate { x, .. } => x % n == sig.r,
        Point::Infinity => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::BITCOIN;
    use num_traits::Num;

    #[test]
    fn test_ecdsa_sign_verify() {
        let _n = &BITCOIN.generator.n;

        let sk = BigInt::from_str_radix(
            "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD",
            16,
        )
        .unwrap();
        let pk = PublicKey::from_sk(&sk, &BITCOIN.generator.g);

        let message = b"user pk1 would like to pay user pk2 1 BTC kkthx";

        let sig = sign(&sk, message);
        assert!(verify(&pk.point, message, &sig));

        let wrong_message = b"user pk1 would like to pay user pk2 2 BTC kkthx";
        assert!(!verify(&pk.point, wrong_message, &sig));
    }

    #[test]
    fn test_rfc6979_deterministic() {
        // same key and message should produce same signature
        let sk = BigInt::from(12345);

        let message = b"test message for RFC 6979";

        let sig1 = sign(&sk, message);
        let sig2 = sign(&sk, message);

        assert_eq!(sig1.r, sig2.r);
        assert_eq!(sig1.s, sig2.s);
    }

    #[test]
    fn test_low_s_normalization() {
        let n = &BITCOIN.generator.n;
        let half_n = n / 2;

        let sk = BigInt::from(999999);
        let message = b"test low s";

        let sig = sign(&sk, message);

        // S should always be in low form
        assert!(sig.s <= half_n, "S value should be normalized to low form");
    }

    #[test]
    fn test_sig_der() {
        let der_hex = "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec";
        let r_hex = "37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6";
        let s_hex = "8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec";

        let r = BigInt::from_str_radix(r_hex, 16).unwrap();
        let s = BigInt::from_str_radix(s_hex, 16).unwrap();

        let sig = Signature {
            r: r.clone(),
            s: s.clone(),
        };
        let encoded = sig.encode();

        assert_eq!(hex::encode(encoded), der_hex.to_lowercase());
    }

    #[test]
    fn test_random_signature_fails() {
        let sk = BigInt::from(123456789);
        let pk = PublicKey::from_sk(&sk, &BITCOIN.generator.g);
        let message = b"test message";

        // Random signature should fail verification
        let random_sig = Signature {
            r: BigInt::from(12345),
            s: BigInt::from(67890),
        };
        assert!(!verify(&pk.point, message, &random_sig));
    }

    #[test]
    fn test_wrong_key_signature() {
        let sk1 = BigInt::from(111);
        let sk2 = BigInt::from(222);
        let pk1 = PublicKey::from_sk(&sk1, &BITCOIN.generator.g);

        let message = b"test wrong key";

        // Sign with sk2, verify with pk1 should fail
        let sig = sign(&sk2, message);
        assert!(!verify(&pk1.point, message, &sig));
    }

    #[test]
    fn test_sign_hash_verify_hash() {
        use crate::sha256::sha256;

        let sk = BigInt::from_str_radix(
            "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD",
            16,
        )
        .unwrap();
        let pk = PublicKey::from_sk(&sk, &BITCOIN.generator.g);

        // simulate a sighash (pre-computed double sha256)
        let message = b"transaction data to sign";
        let z_bytes = sha256(&sha256(message));

        // sign the hash directly
        let sig = sign_hash(&sk, &z_bytes);

        // verify with verify_hash
        assert!(verify_hash(&pk.point, &z_bytes, &sig));

        // wrong hash should fail
        let wrong_z = sha256(&sha256(b"wrong data"));
        assert!(!verify_hash(&pk.point, &wrong_z, &sig));
    }
}
