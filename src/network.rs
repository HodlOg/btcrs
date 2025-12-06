use crate::sha256::sha256;
use crate::utils::encode_varint;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

const MAGICS_MAIN: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
const MAGICS_TEST: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];

#[derive(Debug)]
pub struct NetworkEnvelope {
    pub command: Vec<u8>,
    pub payload: Vec<u8>,
    pub net: String,
}

impl NetworkEnvelope {
    pub fn new(command: &[u8], payload: Vec<u8>, net: &str) -> Self {
        NetworkEnvelope {
            command: command.to_vec(),
            payload,
            net: net.to_string(),
        }
    }

    pub fn decode<R: Read>(reader: &mut R, net: &str) -> Self {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).unwrap();

        let expected_magic = match net {
            "main" => MAGICS_MAIN,
            "test" => MAGICS_TEST,
            _ => panic!("Unknown network"),
        };
        assert_eq!(magic, expected_magic, "Invalid magic bytes");

        let mut command = [0u8; 12];
        reader.read_exact(&mut command).unwrap();
        // Strip trailing nulls
        let cmd_len = command.iter().position(|&x| x == 0).unwrap_or(12);
        let command_vec = command[0..cmd_len].to_vec();

        let mut payload_len_bytes = [0u8; 4];
        reader.read_exact(&mut payload_len_bytes).unwrap();
        let payload_len = u32::from_le_bytes(payload_len_bytes) as usize;

        let mut checksum = [0u8; 4];
        reader.read_exact(&mut checksum).unwrap();

        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).unwrap();

        let hash = sha256(&sha256(&payload));
        assert_eq!(checksum, hash[0..4], "Invalid checksum");

        NetworkEnvelope {
            command: command_vec,
            payload,
            net: net.to_string(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let magic = match self.net.as_str() {
            "main" => MAGICS_MAIN,
            "test" => MAGICS_TEST,
            _ => panic!("Unknown network"),
        };
        out.extend(&magic);

        let mut command = [0u8; 12];
        for (i, &b) in self.command.iter().enumerate().take(12) {
            command[i] = b;
        }
        out.extend(&command);

        out.extend(&(self.payload.len() as u32).to_le_bytes());

        let hash = sha256(&sha256(&self.payload));
        out.extend(&hash[0..4]);

        out.extend(&self.payload);
        out
    }
}

pub trait Message {
    fn command(&self) -> &[u8];
    fn encode(&self) -> Vec<u8>;
}

#[derive(Debug)]
pub struct VersionMessage {
    pub version: u32,
    pub services: u64,
    pub timestamp: u64,
    pub receiver_services: u64,
    pub receiver_ip: [u8; 4],
    pub receiver_port: u16,
    pub sender_services: u64,
    pub sender_ip: [u8; 4],
    pub sender_port: u16,
    pub nonce: u64,
    pub user_agent: Vec<u8>,
    pub latest_block: u32,
    pub relay: bool,
}

impl Default for VersionMessage {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionMessage {
    pub fn new() -> Self {
        VersionMessage {
            version: 70015,
            services: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            receiver_services: 0,
            receiver_ip: [0; 4],
            receiver_port: 8333,
            sender_services: 0,
            sender_ip: [0; 4],
            sender_port: 8333,
            nonce: 0,
            user_agent: b"/bitrs:0.1/".to_vec(),
            latest_block: 0,
            relay: false,
        }
    }
}

impl Message for VersionMessage {
    fn command(&self) -> &[u8] {
        b"version"
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(&self.version.to_le_bytes());
        out.extend(&self.services.to_le_bytes());
        out.extend(&self.timestamp.to_le_bytes());

        // Receiver address
        out.extend(&self.receiver_services.to_le_bytes());
        out.extend(&[0u8; 10]);
        out.extend(&[0xff, 0xff]);
        out.extend(&self.receiver_ip);
        out.extend(&self.receiver_port.to_be_bytes());

        // Sender address
        out.extend(&self.sender_services.to_le_bytes());
        out.extend(&[0u8; 10]);
        out.extend(&[0xff, 0xff]);
        out.extend(&self.sender_ip);
        out.extend(&self.sender_port.to_be_bytes());

        out.extend(&self.nonce.to_le_bytes());

        out.extend(encode_varint(self.user_agent.len() as u64));
        out.extend(&self.user_agent);

        out.extend(&self.latest_block.to_le_bytes());
        out.push(if self.relay { 1 } else { 0 });

        out
    }
}

#[derive(Debug)]
pub struct VerAckMessage;

impl Message for VerAckMessage {
    fn command(&self) -> &[u8] {
        b"verack"
    }

    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }
}

#[derive(Debug)]
pub struct PingMessage {
    pub nonce: u64,
}

impl Message for PingMessage {
    fn command(&self) -> &[u8] {
        b"ping"
    }

    fn encode(&self) -> Vec<u8> {
        self.nonce.to_le_bytes().to_vec()
    }
}

#[derive(Debug)]
pub struct PongMessage {
    pub nonce: u64,
}

impl Message for PongMessage {
    fn command(&self) -> &[u8] {
        b"pong"
    }

    fn encode(&self) -> Vec<u8> {
        self.nonce.to_le_bytes().to_vec()
    }
}

#[derive(Debug)]
pub struct GetHeadersMessage {
    pub version: u32,
    pub num_hashes: u64,
    pub start_block: Vec<u8>,
    pub end_block: Vec<u8>,
}

impl Message for GetHeadersMessage {
    fn command(&self) -> &[u8] {
        b"getheaders"
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(&self.version.to_le_bytes());
        out.extend(encode_varint(self.num_hashes));

        let mut start_rev = self.start_block.clone();
        start_rev.reverse();
        out.extend(start_rev);

        let mut end_rev = self.end_block.clone();
        end_rev.reverse();
        out.extend(end_rev);

        out
    }
}

pub struct SimpleNode {
    stream: TcpStream,
    net: String,
}

impl SimpleNode {
    pub fn new(host: &str, net: &str) -> Self {
        let port = match net {
            "main" => 8333,
            "test" => 18333,
            _ => panic!("Unknown network"),
        };
        let stream = TcpStream::connect(format!("{}:{}", host, port)).unwrap();
        SimpleNode {
            stream,
            net: net.to_string(),
        }
    }

    pub fn send<M: Message>(&mut self, message: &M) {
        let envelope = NetworkEnvelope::new(message.command(), message.encode(), &self.net);
        self.stream.write_all(&envelope.encode()).unwrap();
    }

    pub fn read(&mut self) -> NetworkEnvelope {
        NetworkEnvelope::decode(&mut self.stream, &self.net)
    }

    pub fn handshake(&mut self) {
        let version = VersionMessage::new();
        self.send(&version);

        // wait for version and verack
        let mut version_received = false;
        let mut verack_received = false;

        while !version_received || !verack_received {
            let env = self.read();
            if env.command == b"version" {
                self.send(&VerAckMessage);
                version_received = true;
            } else if env.command == b"verack" {
                verack_received = true;
            }
        }
    }
}
