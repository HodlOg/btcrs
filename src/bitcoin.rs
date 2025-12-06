use crate::curves::{Curve, Generator, Point};
use num_bigint::BigInt;
use num_traits::Num;

pub struct Coin {
    pub generator: Generator,
}

pub fn get_bitcoin_params() -> Coin {
    let p = BigInt::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
    .unwrap();
    let a = BigInt::from(0);
    let b = BigInt::from(7);
    let gx = BigInt::from_str_radix(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        16,
    )
    .unwrap();
    let gy = BigInt::from_str_radix(
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        16,
    )
    .unwrap();
    let n = BigInt::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();

    let curve = Curve { p, a, b };
    let g = Point::new(curve, gx, gy);

    Coin {
        generator: Generator { g, n },
    }
}

lazy_static::lazy_static! {
    pub static ref BITCOIN: Coin = get_bitcoin_params();
}
