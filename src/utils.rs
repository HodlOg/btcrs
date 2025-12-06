use std::io::Read;

#[derive(Debug)]
pub enum ParseError {
    Io(std::io::Error),
    InvalidData(String),
}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "IO error: {}", e),
            ParseError::InvalidData(s) => write!(f, "Invalid data: {}", s),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn decode_int<R: Read>(reader: &mut R, nbytes: usize) -> Result<u64, ParseError> {
    let mut buf = vec![0u8; nbytes];
    reader.read_exact(&mut buf)?;
    let mut res = 0u64;
    for (i, &byte) in buf.iter().enumerate() {
        res |= (byte as u64) << (8 * i);
    }
    Ok(res)
}

pub fn encode_int(i: u64, nbytes: usize) -> Vec<u8> {
    let mut res = Vec::with_capacity(nbytes);
    for j in 0..nbytes {
        res.push(((i >> (8 * j)) & 0xff) as u8);
    }
    res
}

pub fn decode_varint<R: Read>(reader: &mut R) -> Result<u64, ParseError> {
    let i = decode_int(reader, 1)?;
    match i {
        0xfd => decode_int(reader, 2),
        0xfe => decode_int(reader, 4),
        0xff => decode_int(reader, 8),
        _ => Ok(i),
    }
}

pub fn encode_varint(i: u64) -> Vec<u8> {
    if i < 0xfd {
        vec![i as u8]
    } else if i < 0x10000 {
        let mut res = vec![0xfd];
        res.extend(encode_int(i, 2));
        res
    } else if i < 0x100000000 {
        let mut res = vec![0xfe];
        res.extend(encode_int(i, 4));
        res
    } else {
        let mut res = vec![0xff];
        res.extend(encode_int(i, 8));
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_encode_decode_int() {
        let values = [0u64, 1, 255, 256, 65535, 0xdeadbeef, u64::MAX];
        for &val in &values {
            let encoded = encode_int(val, 8);
            let mut cursor = Cursor::new(encoded);
            let decoded = decode_int(&mut cursor, 8).unwrap();
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn test_encode_decode_varint() {
        let values = [
            0u64,
            1,
            0xfc,
            0xfd,
            0xfffe,
            0xffff,
            0x10000,
            0xffffffff,
            u64::MAX,
        ];
        for &val in &values {
            let encoded = encode_varint(val);
            let mut cursor = Cursor::new(encoded);
            let decoded = decode_varint(&mut cursor).unwrap();
            assert_eq!(val, decoded);
        }
    }
}
