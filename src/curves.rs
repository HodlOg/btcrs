use num_bigint::BigInt;
use num_traits::{One, Zero};
use std::ops::{Add, Mul};

#[derive(Clone, Debug, PartialEq)]
pub struct Curve {
    pub p: BigInt,
    pub a: BigInt,
    pub b: BigInt,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Point {
    Infinity,
    Coordinate { x: BigInt, y: BigInt, curve: Curve },
}

impl Point {
    pub fn new(curve: Curve, x: BigInt, y: BigInt) -> Self {
        Point::Coordinate { x, y, curve }
    }

    pub fn infinity() -> Self {
        Point::Infinity
    }

    /// (P + P = 2P)
    pub fn double(&self) -> Point {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Coordinate { x, y, curve } => {
                if y.is_zero() {
                    return Point::Infinity;
                }

                // m = (3 * x^2 + a) * inv(2 * y, p)
                let num = (BigInt::from(3) * x * x + &curve.a) % &curve.p;
                let den = inv(&((BigInt::from(2) * y) % &curve.p), &curve.p);
                let m = (num * den) % &curve.p;

                // rx = m^2 - 2*x
                let rx = (&m * &m - x - x) % &curve.p;
                let rx = (rx + &curve.p) % &curve.p;

                // ry = -(m * (rx - x) + y)
                let ry = -(&m * (&rx - x) + y);
                let ry = (ry % &curve.p + &curve.p) % &curve.p;

                Point::Coordinate {
                    x: rx,
                    y: ry,
                    curve: curve.clone(),
                }
            }
        }
    }
}

pub fn extended_euclidean_algorithm(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let mut old_r = a.clone();
    let mut r = b.clone();
    let mut old_s = BigInt::one();
    let mut s = BigInt::zero();
    let mut old_t = BigInt::zero();
    let mut t = BigInt::one();

    while !r.is_zero() {
        let quotient = &old_r / &r;
        let temp_r = r.clone();
        r = old_r - &quotient * &r;
        old_r = temp_r;

        let temp_s = s.clone();
        s = old_s - &quotient * &s;
        old_s = temp_s;

        let temp_t = t.clone();
        t = old_t - &quotient * &t;
        old_t = temp_t;
    }

    (old_r, old_s, old_t)
}

pub fn inv(n: &BigInt, p: &BigInt) -> BigInt {
    let (_, x, _) = extended_euclidean_algorithm(n, p);
    (x % p + p) % p
}

impl Add for Point {
    type Output = Point;

    fn add(self, other: Point) -> Point {
        match (self, other) {
            (Point::Infinity, p) => p,
            (p, Point::Infinity) => p,
            (
                Point::Coordinate {
                    x: x1,
                    y: y1,
                    curve: c1,
                },
                Point::Coordinate {
                    x: x2,
                    y: y2,
                    curve: c2,
                },
            ) => {
                if c1 != c2 {
                    panic!("Cannot add points on different curves");
                }

                if x1 == x2 && y1 != y2 {
                    return Point::Infinity;
                }

                let m = if x1 == x2 {
                    if y1.is_zero() {
                        return Point::Infinity;
                    }
                    // m = (3 * x1^2 + a) * inv(2 * y1, p)
                    let num = (BigInt::from(3) * &x1 * &x1 + &c1.a) % &c1.p;
                    let den = inv(&((BigInt::from(2) * &y1) % &c1.p), &c1.p);
                    (num * den) % &c1.p
                } else {
                    // m = (y1 - y2) * inv(x1 - x2, p)
                    let num = (&y1 - &y2 + &c1.p) % &c1.p;
                    let den = inv(&((&x1 - &x2 + &c1.p) % &c1.p), &c1.p);
                    (num * den) % &c1.p
                };

                // rx = m^2 - x1 - x2
                let rx = (&m * &m - &x1 - &x2) % &c1.p;
                let rx = (rx + &c1.p) % &c1.p;

                // ry = -(m * (rx - x1) + y1)
                let ry = -(&m * (&rx - &x1) + &y1);
                let ry = (ry % &c1.p + &c1.p) % &c1.p;

                Point::Coordinate {
                    x: rx,
                    y: ry,
                    curve: c1,
                }
            }
        }
    }
}

// Implement reference addition to avoid moving
impl<'b> Add<&'b Point> for &Point {
    type Output = Point;

    fn add(self, other: &'b Point) -> Point {
        self.clone() + other.clone()
    }
}

fn montgomery_ladder(p: &Point, k: &BigInt) -> Point {
    if k.is_zero() {
        return Point::Infinity;
    }

    let curve = match p {
        Point::Infinity => return Point::Infinity,
        Point::Coordinate { curve, .. } => curve.clone(),
    };

    let bits = k.bits() as usize;
    if bits == 0 {
        return Point::Infinity;
    }

    let mut r0 = Point::Infinity;
    let mut r1 = p.clone();

    for i in (0..bits).rev() {
        let bit = (k >> i) & BigInt::one();

        if bit.is_zero() {
            // r1 = r0 + r1
            // r0 = 2 * r0
            r1 = &r0 + &r1;
            r0 = r0.double();
        } else {
            // r0 = r0 + r1
            // r1 = 2 * r1
            r0 = &r0 + &r1;
            r1 = r1.double();
        }
    }

    match r0 {
        Point::Infinity => Point::Infinity,
        Point::Coordinate { x, y, .. } => {
            let x = (x % &curve.p + &curve.p) % &curve.p;
            let y = (y % &curve.p + &curve.p) % &curve.p;
            Point::Coordinate { x, y, curve }
        }
    }
}

impl Mul<BigInt> for Point {
    type Output = Point;

    fn mul(self, k: BigInt) -> Point {
        montgomery_ladder(&self, &k)
    }
}

// reference
impl<'a> Mul<&'a BigInt> for &'a Point {
    type Output = Point;

    fn mul(self, k: &'a BigInt) -> Point {
        montgomery_ladder(self, k)
    }
}

#[derive(Clone, Debug)]
pub struct Generator {
    pub g: Point,
    pub n: BigInt,
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Num;

    fn secp256k1_curve() -> Curve {
        Curve {
            p: BigInt::from_str_radix(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
                16,
            )
            .unwrap(),
            a: BigInt::from(0),
            b: BigInt::from(7),
        }
    }

    fn secp256k1_generator() -> Point {
        let curve = secp256k1_curve();
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
        Point::new(curve, gx, gy)
    }

    #[test]
    fn test_point_double() {
        let g = secp256k1_generator();
        let g2 = g.double();

        // 2G should not be infinity
        assert!(matches!(g2, Point::Coordinate { .. }));

        // 2G should equal G + G
        let g_plus_g = &g + &g;
        assert_eq!(g2, g_plus_g);
    }

    #[test]
    fn test_montgomery_ladder() {
        let g = secp256k1_generator();

        // Test small scalars
        let k1 = BigInt::from(1);
        let result1 = &g * &k1;
        assert_eq!(result1, g);

        let k2 = BigInt::from(2);
        let result2 = &g * &k2;
        assert_eq!(result2, g.double());

        // Test that k*G using montgomery ladder matches regular addition
        let k3 = BigInt::from(7);
        let result3 = &g * &k3;

        // Compute 7*G manually
        let mut manual = g.clone();
        for _ in 1..7 {
            manual = &manual + &g;
        }
        assert_eq!(result3, manual);
    }

    #[test]
    fn test_known_public_key() {
        // Known test vector
        let g = secp256k1_generator();
        let sk = BigInt::from_str_radix(
            "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD",
            16,
        )
        .unwrap();

        let pk = &g * &sk;

        match pk {
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
            Point::Infinity => panic!("Expected coordinate point"),
        }
    }
}
