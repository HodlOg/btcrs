use std::convert::TryInto;

const K: [u32; 5] = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
const KK: [u32; 5] = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];

fn rol(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

fn f0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn f1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

fn f2(x: u32, y: u32, z: u32) -> u32 {
    (x | !y) ^ z
}

fn f3(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (!z & y)
}

fn f4(x: u32, y: u32, z: u32) -> u32 {
    x ^ (y | !z)
}

#[allow(clippy::too_many_arguments)]
fn r(
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    f: fn(u32, u32, u32) -> u32,
    k: u32,
    s: u32,
    x: u32,
) -> (u32, u32) {
    let t = a.wrapping_add(f(b, c, d)).wrapping_add(x).wrapping_add(k);
    let a = rol(t, s).wrapping_add(e);
    let c = rol(c, 10);
    (a, c)
}

pub fn ripemd160(data: &[u8]) -> Vec<u8> {
    let mut state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() * 8) % 512 != 448 {
        padded.push(0x00);
    }
    let bit_len = (data.len() as u64) * 8;
    padded.extend_from_slice(&bit_len.to_le_bytes()); // little endian for ripemd160

    // this is taken from the reference implementation
    for chunk in padded.chunks(64) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];

        // Round 1
        let (na, nc) = r(a, b, c, d, e, f0, K[0], 11, x[0]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f0, K[0], 14, x[1]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f0, K[0], 15, x[2]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f0, K[0], 12, x[3]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f0, K[0], 5, x[4]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f0, K[0], 8, x[5]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f0, K[0], 7, x[6]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f0, K[0], 9, x[7]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f0, K[0], 11, x[8]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f0, K[0], 13, x[9]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f0, K[0], 14, x[10]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f0, K[0], 15, x[11]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f0, K[0], 6, x[12]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f0, K[0], 7, x[13]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f0, K[0], 9, x[14]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f0, K[0], 8, x[15]);
        a = na;
        c = nc;

        // Round 2
        let (ne, nb) = r(e, a, b, c, d, f1, K[1], 7, x[7]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f1, K[1], 6, x[4]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f1, K[1], 8, x[13]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f1, K[1], 13, x[1]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f1, K[1], 11, x[10]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f1, K[1], 9, x[6]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f1, K[1], 7, x[15]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f1, K[1], 15, x[3]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f1, K[1], 7, x[12]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f1, K[1], 12, x[0]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f1, K[1], 15, x[9]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f1, K[1], 9, x[5]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f1, K[1], 11, x[2]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f1, K[1], 7, x[14]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f1, K[1], 13, x[11]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f1, K[1], 12, x[8]);
        e = ne;
        b = nb;

        // Round 3
        let (nd, na) = r(d, e, a, b, c, f2, K[2], 11, x[3]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f2, K[2], 13, x[10]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f2, K[2], 6, x[14]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f2, K[2], 7, x[4]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f2, K[2], 14, x[9]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f2, K[2], 9, x[15]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f2, K[2], 13, x[8]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f2, K[2], 15, x[1]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f2, K[2], 14, x[2]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f2, K[2], 8, x[7]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f2, K[2], 13, x[0]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f2, K[2], 6, x[6]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f2, K[2], 5, x[13]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f2, K[2], 12, x[11]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f2, K[2], 7, x[5]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f2, K[2], 5, x[12]);
        d = nd;
        a = na;

        // Round 4
        let (nc, ne) = r(c, d, e, a, b, f3, K[3], 11, x[1]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f3, K[3], 12, x[9]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f3, K[3], 14, x[11]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f3, K[3], 15, x[10]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f3, K[3], 14, x[0]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f3, K[3], 15, x[8]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f3, K[3], 9, x[12]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f3, K[3], 8, x[4]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f3, K[3], 9, x[13]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f3, K[3], 14, x[3]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f3, K[3], 5, x[7]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f3, K[3], 6, x[15]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f3, K[3], 8, x[14]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f3, K[3], 6, x[5]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f3, K[3], 5, x[6]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f3, K[3], 12, x[2]);
        c = nc;
        e = ne;

        // Round 5
        let (nb, nd) = r(b, c, d, e, a, f4, K[4], 9, x[4]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f4, K[4], 15, x[0]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f4, K[4], 5, x[5]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f4, K[4], 11, x[9]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f4, K[4], 6, x[7]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f4, K[4], 8, x[12]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f4, K[4], 13, x[2]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f4, K[4], 12, x[10]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f4, K[4], 5, x[14]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f4, K[4], 12, x[1]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f4, K[4], 13, x[3]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f4, K[4], 14, x[8]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f4, K[4], 11, x[11]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f4, K[4], 8, x[6]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f4, K[4], 5, x[15]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f4, K[4], 6, x[13]);
        b = nb;
        d = nd;

        let aa = a;
        let bb = b;
        let cc = c;
        let dd = d;
        let ee = e;

        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];

        // Parallel Round 1
        let (na, nc) = r(a, b, c, d, e, f4, KK[0], 8, x[5]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f4, KK[0], 9, x[14]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f4, KK[0], 9, x[7]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f4, KK[0], 11, x[0]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f4, KK[0], 13, x[9]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f4, KK[0], 15, x[2]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f4, KK[0], 15, x[11]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f4, KK[0], 5, x[4]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f4, KK[0], 7, x[13]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f4, KK[0], 7, x[6]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f4, KK[0], 8, x[15]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f4, KK[0], 11, x[8]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f4, KK[0], 14, x[1]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f4, KK[0], 14, x[10]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f4, KK[0], 12, x[3]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f4, KK[0], 6, x[12]);
        a = na;
        c = nc;

        // Parallel Round 2
        let (ne, nb) = r(e, a, b, c, d, f3, KK[1], 9, x[6]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f3, KK[1], 13, x[11]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f3, KK[1], 15, x[3]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f3, KK[1], 7, x[7]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f3, KK[1], 12, x[0]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f3, KK[1], 8, x[13]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f3, KK[1], 9, x[5]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f3, KK[1], 11, x[10]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f3, KK[1], 7, x[14]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f3, KK[1], 7, x[15]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f3, KK[1], 12, x[8]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f3, KK[1], 7, x[12]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f3, KK[1], 6, x[4]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f3, KK[1], 15, x[9]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f3, KK[1], 13, x[1]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f3, KK[1], 11, x[2]);
        e = ne;
        b = nb;

        // Parallel Round 3
        let (nd, na) = r(d, e, a, b, c, f2, KK[2], 9, x[15]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f2, KK[2], 7, x[5]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f2, KK[2], 15, x[1]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f2, KK[2], 11, x[3]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f2, KK[2], 8, x[7]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f2, KK[2], 6, x[14]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f2, KK[2], 6, x[6]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f2, KK[2], 14, x[9]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f2, KK[2], 12, x[11]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f2, KK[2], 13, x[8]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f2, KK[2], 5, x[12]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f2, KK[2], 14, x[2]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f2, KK[2], 13, x[10]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f2, KK[2], 13, x[0]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f2, KK[2], 7, x[4]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f2, KK[2], 5, x[13]);
        d = nd;
        a = na;

        // Parallel Round 4
        let (nc, ne) = r(c, d, e, a, b, f1, KK[3], 15, x[8]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f1, KK[3], 5, x[6]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f1, KK[3], 8, x[4]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f1, KK[3], 11, x[1]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f1, KK[3], 14, x[3]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f1, KK[3], 14, x[11]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f1, KK[3], 6, x[15]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f1, KK[3], 14, x[0]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f1, KK[3], 6, x[5]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f1, KK[3], 9, x[12]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f1, KK[3], 12, x[2]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f1, KK[3], 9, x[13]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f1, KK[3], 12, x[9]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f1, KK[3], 5, x[7]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f1, KK[3], 15, x[10]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f1, KK[3], 8, x[14]);
        c = nc;
        e = ne;

        // Parallel Round 5
        let (nb, nd) = r(b, c, d, e, a, f0, KK[4], 8, x[12]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f0, KK[4], 5, x[15]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f0, KK[4], 12, x[10]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f0, KK[4], 9, x[4]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f0, KK[4], 12, x[1]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f0, KK[4], 5, x[5]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f0, KK[4], 14, x[8]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f0, KK[4], 6, x[7]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f0, KK[4], 8, x[6]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f0, KK[4], 13, x[2]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f0, KK[4], 6, x[13]);
        b = nb;
        d = nd;
        let (na, nc) = r(a, b, c, d, e, f0, KK[4], 5, x[14]);
        a = na;
        c = nc;
        let (ne, nb) = r(e, a, b, c, d, f0, KK[4], 15, x[0]);
        e = ne;
        b = nb;
        let (nd, na) = r(d, e, a, b, c, f0, KK[4], 13, x[3]);
        d = nd;
        a = na;
        let (nc, ne) = r(c, d, e, a, b, f0, KK[4], 11, x[9]);
        c = nc;
        e = ne;
        let (nb, nd) = r(b, c, d, e, a, f0, KK[4], 11, x[11]);
        b = nb;
        d = nd;

        let t = state[1].wrapping_add(cc).wrapping_add(d);
        state[1] = state[2].wrapping_add(dd).wrapping_add(e);
        state[2] = state[3].wrapping_add(ee).wrapping_add(a);
        state[3] = state[4].wrapping_add(aa).wrapping_add(b);
        state[4] = state[0].wrapping_add(bb).wrapping_add(c);
        state[0] = t;
    }

    let mut result = Vec::new();
    for val in state.iter() {
        result.extend_from_slice(&val.to_le_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ripemd160_empty() {
        let data = b"";
        let hash = ripemd160(data);
        assert_eq!(
            hex::encode(hash),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
    }

    #[test]
    fn test_ripemd160_abc() {
        let data = b"abc";
        let hash = ripemd160(data);
        assert_eq!(
            hex::encode(hash),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }
}
