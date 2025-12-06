use crate::bitcoin::BITCOIN;
use crate::curves::Point;
use crate::ripemd160::ripemd160;
use crate::sha256::sha256;
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use rand::RngCore;

pub fn gen_secret_key(n: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    loop {
        rng.fill_bytes(&mut bytes);
        let key = BigInt::from_bytes_be(Sign::Plus, &bytes);
        if key >= BigInt::from(1) && key < *n {
            return key;
        }
    }
}

pub struct PublicKey {
    pub point: Point,
}

impl PublicKey {
    pub fn new(point: Point) -> Self {
        PublicKey { point }
    }

    pub fn from_sk(sk: &BigInt, g: &Point) -> Self {
        let pk = g * sk;
        PublicKey { point: pk }
    }

    pub fn encode(&self, compressed: bool, hash160: bool) -> Vec<u8> {
        let (x, y) = match &self.point {
            Point::Coordinate { x, y, curve: _ } => (x, y),
            Point::Infinity => panic!("Cannot encode point at infinity"),
        };

        let mut pkb = Vec::new();
        if compressed {
            let prefix = if y % 2u8 == BigInt::from(0) {
                0x02
            } else {
                0x03
            };
            pkb.push(prefix);
            let x_bytes = x.to_bytes_be().1;
            // Pad x to 32 bytes
            let mut padded_x = vec![0u8; 32 - x_bytes.len()];
            padded_x.extend(x_bytes);
            pkb.extend(padded_x);
        } else {
            pkb.push(0x04);
            let x_bytes = x.to_bytes_be().1;
            let y_bytes = y.to_bytes_be().1;

            let mut padded_x = vec![0u8; 32 - x_bytes.len()];
            padded_x.extend(x_bytes);
            pkb.extend(padded_x);

            let mut padded_y = vec![0u8; 32 - y_bytes.len()];
            padded_y.extend(y_bytes);
            pkb.extend(padded_y);
        }

        if hash160 {
            ripemd160(&sha256(&pkb))
        } else {
            pkb
        }
    }

    pub fn address(&self, net: &str, compressed: bool) -> String {
        let pkb_hash = self.encode(compressed, true);
        let version = match net {
            "main" => 0x00,
            "test" => 0x6f,
            _ => panic!("Unknown network"),
        };

        let mut ver_pkb_hash = Vec::new();
        ver_pkb_hash.push(version);
        ver_pkb_hash.extend(pkb_hash);

        let checksum = sha256(&sha256(&ver_pkb_hash));
        let mut byte_address = ver_pkb_hash.clone();
        byte_address.extend_from_slice(&checksum[0..4]);

        b58encode(&byte_address)
    }

    /// decode a public key from bytes (sec format)
    /// supports both compressed (33 bytes) and uncompressed (65 bytes) formats.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let curve = &BITCOIN.generator.g;
        let (curve_p, curve_a, curve_b) = match curve {
            Point::Coordinate { curve, .. } => (&curve.p, &curve.a, &curve.b),
            Point::Infinity => return None,
        };

        match data[0] {
            // uncompressed 0x04 || x (32 bytes) || y (32 bytes)
            0x04 => {
                if data.len() != 65 {
                    return None;
                }
                let x = BigInt::from_bytes_be(Sign::Plus, &data[1..33]);
                let y = BigInt::from_bytes_be(Sign::Plus, &data[33..65]);

                let curve = crate::curves::Curve {
                    p: curve_p.clone(),
                    a: curve_a.clone(),
                    b: curve_b.clone(),
                };
                Some(PublicKey {
                    point: Point::new(curve, x, y),
                })
            }
            // compressed: 0x02 (even y) or 0x03 (odd y) || x (32 bytes)
            0x02 | 0x03 => {
                if data.len() != 33 {
                    return None;
                }
                let x = BigInt::from_bytes_be(Sign::Plus, &data[1..33]);
                let is_odd = data[0] == 0x03;

                // Recover y from x using the curve equation: y² = x³ + ax + b (mod p)
                // For secp256k1: y² = x³ + 7 (mod p)
                let x_cubed = (&x * &x * &x) % curve_p;
                let ax = (curve_a * &x) % curve_p;
                let y_squared = (x_cubed + ax + curve_b) % curve_p;

                // Compute modular square root using Tonelli-Shanks
                // For secp256k1, p ≡ 3 (mod 4), so y = y_squared^((p+1)/4) mod p
                let exp = (curve_p + 1u32) / 4u32;
                let y = mod_pow(&y_squared, &exp, curve_p);

                // Choose the correct y based on parity
                let y = if (y.clone() % 2u32 == BigInt::from(1)) == is_odd {
                    y
                } else {
                    curve_p - &y
                };

                let curve = crate::curves::Curve {
                    p: curve_p.clone(),
                    a: curve_a.clone(),
                    b: curve_b.clone(),
                };
                Some(PublicKey {
                    point: Point::new(curve, x, y),
                })
            }
            _ => None,
        }
    }
}

/// modular exponentiation: base^exp mod modulus
fn mod_pow(base: &BigInt, exp: &BigInt, modulus: &BigInt) -> BigInt {
    use num_traits::{One, Zero};

    if modulus.is_one() {
        return BigInt::zero();
    }

    let mut result = BigInt::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();

    while exp > BigInt::zero() {
        if &exp % 2u32 == BigInt::one() {
            result = (&result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }

    result
}

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn b58encode(b: &[u8]) -> String {
    let mut n = BigInt::from_bytes_be(Sign::Plus, b);
    let mut chars = Vec::new();
    let base = BigInt::from(58);
    let zero = BigInt::from(0);

    while n > zero {
        let remainder = &n % &base;
        n /= &base;
        chars.push(ALPHABET[remainder.to_usize().unwrap()] as char);
    }

    let mut num_leading_zeros = 0;
    for byte in b {
        if *byte == 0 {
            num_leading_zeros += 1;
        } else {
            break;
        }
    }

    let mut res = String::new();
    for _ in 0..num_leading_zeros {
        res.push(ALPHABET[0] as char);
    }
    res.extend(chars.iter().rev());
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::BITCOIN;
    use num_traits::Num;

    #[test]
    fn test_public_key_gen() {
        let sk_hex = "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD";
        let sk = BigInt::from_str_radix(sk_hex, 16).unwrap();
        let pk = PublicKey::from_sk(&sk, &BITCOIN.generator.g);

        match pk.point {
            Point::Coordinate { x, y, .. } => {
                let x_hex = format!("{:064X}", x);
                let y_hex = format!("{:064X}", y);
                assert_eq!(
                    x_hex,
                    "F028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A"
                );
                assert_eq!(
                    y_hex,
                    "07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BDB"
                );
            }
            Point::Infinity => panic!("Point at infinity"),
        }
    }

    #[test]
    fn test_btc_addresses() {
        let tests = vec![
            (
                "main",
                true,
                "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6",
                "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3",
            ),
            (
                "main",
                true,
                "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725",
                "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
            ),
            (
                "main",
                true,
                "12345deadbeef",
                "1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1",
            ),
            ("test", false, "138a", "mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA"), // 5002 in hex is 138a
        ];

        for (net, compressed, sk_str, expected) in tests {
            let sk = BigInt::from_str_radix(sk_str, 16).unwrap();
            let pk = PublicKey::from_sk(&sk, &BITCOIN.generator.g);
            let addr = pk.address(net, compressed);
            assert_eq!(addr, expected);
        }

        // power cases separately - 2020**5 with compressed public key on testnet
        let sk = BigInt::from(2020u64).pow(5);
        let pk = PublicKey::from_sk(&sk, &BITCOIN.generator.g);
        let addr = pk.address("test", true);
        assert_eq!(addr, "mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH");
    }
}
