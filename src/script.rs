//! bitcoin script interpreter.
//!
//! a stack based vm for executing bitcoin scripts.
//! supports: p2pkh (pay to public key hash), some op codes (no branching)
//! this will requre some work and changes

use crate::ecdsa::{verify_hash, Signature};
use crate::keys::PublicKey;
use crate::ripemd160::ripemd160;
use crate::sha256::sha256;
use crate::transaction::{Script, ScriptCmd, Tx};

// opcode constants, not nice, but works for now
// push value
pub const OP_0: u8 = 0x00;
pub const OP_FALSE: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_1: u8 = 0x51;
pub const OP_TRUE: u8 = 0x51;
pub const OP_2: u8 = 0x52;
pub const OP_3: u8 = 0x53;
pub const OP_4: u8 = 0x54;
pub const OP_5: u8 = 0x55;
pub const OP_6: u8 = 0x56;
pub const OP_7: u8 = 0x57;
pub const OP_8: u8 = 0x58;
pub const OP_9: u8 = 0x59;
pub const OP_10: u8 = 0x5a;
pub const OP_11: u8 = 0x5b;
pub const OP_12: u8 = 0x5c;
pub const OP_13: u8 = 0x5d;
pub const OP_14: u8 = 0x5e;
pub const OP_15: u8 = 0x5f;
pub const OP_16: u8 = 0x60; // 96

// flow
pub const OP_NOP: u8 = 0x61;
pub const OP_IF: u8 = 0x63;
pub const OP_NOTIF: u8 = 0x64;
pub const OP_ELSE: u8 = 0x67;
pub const OP_ENDIF: u8 = 0x68;
pub const OP_VERIFY: u8 = 0x69;
pub const OP_RETURN: u8 = 0x6a;

// stack
pub const OP_TOALTSTACK: u8 = 0x6b;
pub const OP_FROMALTSTACK: u8 = 0x6c;
pub const OP_IFDUP: u8 = 0x73;
pub const OP_DEPTH: u8 = 0x74;
pub const OP_DROP: u8 = 0x75;
pub const OP_DUP: u8 = 0x76;
pub const OP_NIP: u8 = 0x77;
pub const OP_OVER: u8 = 0x78;
pub const OP_PICK: u8 = 0x79;
pub const OP_ROLL: u8 = 0x7a;
pub const OP_ROT: u8 = 0x7b;
pub const OP_SWAP: u8 = 0x7c;
pub const OP_TUCK: u8 = 0x7d;
pub const OP_2DROP: u8 = 0x6d;
pub const OP_2DUP: u8 = 0x6e;
pub const OP_3DUP: u8 = 0x6f;
pub const OP_2OVER: u8 = 0x70;
pub const OP_2ROT: u8 = 0x71;
pub const OP_2SWAP: u8 = 0x72;

// splice operations
pub const OP_SIZE: u8 = 0x82; // 130

// bitwise logic
pub const OP_EQUAL: u8 = 0x87; // 135
pub const OP_EQUALVERIFY: u8 = 0x88; // 136

// arithmetic
pub const OP_1ADD: u8 = 0x8b; // 139
pub const OP_1SUB: u8 = 0x8c; // 140
pub const OP_NEGATE: u8 = 0x8f; // 143
pub const OP_ABS: u8 = 0x90; // 144
pub const OP_NOT: u8 = 0x91; // 145
pub const OP_0NOTEQUAL: u8 = 0x92; // 146
pub const OP_ADD: u8 = 0x93; // 147
pub const OP_SUB: u8 = 0x94; // 148
pub const OP_BOOLAND: u8 = 0x9a; // 154
pub const OP_BOOLOR: u8 = 0x9b; // 155
pub const OP_NUMEQUAL: u8 = 0x9c; // 156
pub const OP_NUMEQUALVERIFY: u8 = 0x9d; // 157
pub const OP_NUMNOTEQUAL: u8 = 0x9e; // 158
pub const OP_LESSTHAN: u8 = 0x9f; // 159
pub const OP_GREATERTHAN: u8 = 0xa0; // 160
pub const OP_LESSTHANOREQUAL: u8 = 0xa1; // 161
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2; // 162
pub const OP_MIN: u8 = 0xa3; // 163
pub const OP_MAX: u8 = 0xa4; // 164
pub const OP_WITHIN: u8 = 0xa5; // 165

// crypto
pub const OP_RIPEMD160: u8 = 0xa6; // 166
pub const OP_SHA1: u8 = 0xa7; // 167
pub const OP_SHA256: u8 = 0xa8; // 168
pub const OP_HASH160: u8 = 0xa9; // 169 - SHA256 then RIPEMD160
pub const OP_HASH256: u8 = 0xaa; // 170 - Double SHA256
pub const OP_CODESEPARATOR: u8 = 0xab; // 171
pub const OP_CHECKSIG: u8 = 0xac; // 172
pub const OP_CHECKSIGVERIFY: u8 = 0xad; // 173
pub const OP_CHECKMULTISIG: u8 = 0xae; // 174
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf; // 175

// locktime
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1; // 177
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2; // 178

// ============================================================================
// Script Error Types
// ============================================================================

/// Errors that can occur during script execution.
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptError {
    /// not enough elements
    StackUnderflow,
    InvalidOpcode(u8),
    /// op_verify failed - top of stack was false
    VerifyFailed,
    /// op_equalverify failed - values not equal
    EqualVerifyFailed,
    /// op_checksig or op_checksigverify failed
    SigVerifyFailed,
    /// script ended with false or empty stack
    ScriptFailed,
    /// invalid public key encoding
    InvalidPublicKey,
    /// invalid signature encoding
    InvalidSignature,
    /// op_return encountered (marks output as unspendable)
    OpReturn,
    /// disabled opcode used
    DisabledOpcode(u8),
    /// script is too large
    ScriptTooLarge,
    /// stack size exceeded
    StackOverflow,
    /// negative locktime
    NegativeLocktime,
    /// unsatisfied locktime
    UnsatisfiedLocktime,
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptError::StackUnderflow => write!(f, "Stack underflow"),
            ScriptError::InvalidOpcode(op) => write!(f, "Invalid opcode: 0x{:02x}", op),
            ScriptError::VerifyFailed => write!(f, "OP_VERIFY failed"),
            ScriptError::EqualVerifyFailed => write!(f, "OP_EQUALVERIFY failed"),
            ScriptError::SigVerifyFailed => write!(f, "Signature verification failed"),
            ScriptError::ScriptFailed => write!(f, "Script evaluation failed"),
            ScriptError::InvalidPublicKey => write!(f, "Invalid public key"),
            ScriptError::InvalidSignature => write!(f, "Invalid signature"),
            ScriptError::OpReturn => write!(f, "OP_RETURN encountered"),
            ScriptError::DisabledOpcode(op) => write!(f, "Disabled opcode: 0x{:02x}", op),
            ScriptError::ScriptTooLarge => write!(f, "Script too large"),
            ScriptError::StackOverflow => write!(f, "Stack overflow"),
            ScriptError::NegativeLocktime => write!(f, "Negative locktime"),
            ScriptError::UnsatisfiedLocktime => write!(f, "Unsatisfied locktime"),
        }
    }
}

impl std::error::Error for ScriptError {}

pub type ScriptResult<T> = Result<T, ScriptError>;
pub struct ScriptContext<'a> {
    pub tx: &'a Tx,
    pub input_index: usize,
}

pub struct ScriptInterpreter {
    stack: Vec<Vec<u8>>,
    /// (for OP_TOALTSTACK/OP_FROMALTSTACK)
    alt_stack: Vec<Vec<u8>>,
}

impl Default for ScriptInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptInterpreter {
    pub fn new() -> Self {
        ScriptInterpreter {
            stack: Vec::new(),
            alt_stack: Vec::new(),
        }
    }

    pub fn stack(&self) -> &[Vec<u8>] {
        &self.stack
    }

    /// (nonzero, nonnegative zero).
    fn is_true(data: &[u8]) -> bool {
        for (i, &byte) in data.iter().enumerate() {
            if byte != 0 {
                if i == data.len() - 1 && byte == 0x80 {
                    return false;
                }
                return true;
            }
        }
        false
    }

    /// encode a number as script bytes (little-endian with sign bit).
    fn encode_num(n: i64) -> Vec<u8> {
        if n == 0 {
            return vec![];
        }

        let negative = n < 0;
        let mut abs_n = n.unsigned_abs();
        let mut result = Vec::new();

        while abs_n > 0 {
            result.push((abs_n & 0xff) as u8);
            abs_n >>= 8;
        }

        // add an extra byte for the sign
        if result.last().map(|&b| b & 0x80 != 0).unwrap_or(false) {
            result.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            let last = result.len() - 1;
            result[last] |= 0x80;
        }

        result
    }

    /// decode script bytes to a number (little-endian with sign bit).
    fn decode_num(data: &[u8]) -> i64 {
        if data.is_empty() {
            return 0;
        }
        let mut result: i64 = 0;
        for (i, &byte) in data.iter().enumerate() {
            result |= (byte as i64) << (8 * i);
        }

        if data.last().map(|&b| b & 0x80 != 0).unwrap_or(false) {
            let sign_bit_pos = 8 * (data.len() - 1) + 7;
            result &= !(1i64 << sign_bit_pos);
            result = -result;
        }

        result
    }

    fn push(&mut self, data: Vec<u8>) -> ScriptResult<()> {
        if self.stack.len() >= 1000 {
            return Err(ScriptError::StackOverflow);
        }
        self.stack.push(data);
        Ok(())
    }

    fn pop(&mut self) -> ScriptResult<Vec<u8>> {
        self.stack.pop().ok_or(ScriptError::StackUnderflow)
    }

    fn peek(&self) -> ScriptResult<&Vec<u8>> {
        self.stack.last().ok_or(ScriptError::StackUnderflow)
    }

    fn execute_op(&mut self, op: u8, context: Option<&ScriptContext>) -> ScriptResult<()> {
        match op {
            // (op_0 through op_16)
            OP_0 => self.push(vec![])?,
            
            op @ OP_1..=OP_16 => {
                let n = (op - OP_1 + 1) as i64;
                self.push(Self::encode_num(n))?;
            }
            
            OP_1NEGATE => self.push(Self::encode_num(-1))?,

            // stack operations
            OP_NOP => {}
            
            OP_DUP => {
                let top = self.peek()?.clone();
                self.push(top)?;
            }
            
            OP_DROP => {
                self.pop()?;
            }
            
            OP_2DROP => {
                self.pop()?;
                self.pop()?;
            }
            
            OP_2DUP => {
                if self.stack.len() < 2 {
                    return Err(ScriptError::StackUnderflow);
                }
                let a = self.stack[self.stack.len() - 2].clone();
                let b = self.stack[self.stack.len() - 1].clone();
                self.push(a)?;
                self.push(b)?;
            }
            
            OP_SWAP => {
                if self.stack.len() < 2 {
                    return Err(ScriptError::StackUnderflow);
                }
                let len = self.stack.len();
                self.stack.swap(len - 1, len - 2);
            }
            
            OP_OVER => {
                if self.stack.len() < 2 {
                    return Err(ScriptError::StackUnderflow);
                }
                let item = self.stack[self.stack.len() - 2].clone();
                self.push(item)?;
            }
            
            OP_ROT => {
                if self.stack.len() < 3 {
                    return Err(ScriptError::StackUnderflow);
                }
                let len = self.stack.len();
                let item = self.stack.remove(len - 3);
                self.stack.push(item);
            }
            
            OP_NIP => {
                if self.stack.len() < 2 {
                    return Err(ScriptError::StackUnderflow);
                }
                let len = self.stack.len();
                self.stack.remove(len - 2);
            }
            
            OP_TUCK => {
                if self.stack.len() < 2 {
                    return Err(ScriptError::StackUnderflow);
                }
                let top = self.stack.last().unwrap().clone();
                let len = self.stack.len();
                self.stack.insert(len - 2, top);
            }

            OP_IFDUP => {
                let top = self.peek()?.clone();
                if Self::is_true(&top) {
                    self.push(top)?;
                }
            }

            OP_DEPTH => {
                let depth = self.stack.len() as i64;
                self.push(Self::encode_num(depth))?;
            }

            OP_SIZE => {
                let top = self.peek()?;
                let size = top.len() as i64;
                self.push(Self::encode_num(size))?;
            }

            OP_TOALTSTACK => {
                let item = self.pop()?;
                self.alt_stack.push(item);
            }

            OP_FROMALTSTACK => {
                let item = self.alt_stack.pop().ok_or(ScriptError::StackUnderflow)?;
                self.push(item)?;
            }

            // Verification
            OP_VERIFY => {
                let top = self.pop()?;
                if !Self::is_true(&top) {
                    return Err(ScriptError::VerifyFailed);
                }
            }
            
            OP_RETURN => {
                return Err(ScriptError::OpReturn);
            }

            // Equality
            OP_EQUAL => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = if a == b { vec![1] } else { vec![] };
                self.push(result)?;
            }
            
            OP_EQUALVERIFY => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a != b {
                    return Err(ScriptError::EqualVerifyFailed);
                }
            }

            OP_RIPEMD160 => {
                let data = self.pop()?;
                let hash = ripemd160(&data);
                self.push(hash)?;
            }
            
            OP_SHA256 => {
                let data = self.pop()?;
                let hash = sha256(&data);
                self.push(hash)?;
            }
            
            OP_HASH160 => {
                // HASH160 = RIPEMD160(SHA256(x))
                let data = self.pop()?;
                let hash = ripemd160(&sha256(&data));
                self.push(hash)?;
            }
            
            OP_HASH256 => {
                // HASH256 = SHA256(SHA256(x))
                let data = self.pop()?;
                let hash = sha256(&sha256(&data));
                self.push(hash)?;
            }
            
            OP_CHECKSIG => {
                let pubkey_bytes = self.pop()?;
                let sig_bytes = self.pop()?;
                
                let result = self.verify_signature(&sig_bytes, &pubkey_bytes, context)?;
                self.push(if result { vec![1] } else { vec![] })?;
            }
            
            OP_CHECKSIGVERIFY => {
                let pubkey_bytes = self.pop()?;
                let sig_bytes = self.pop()?;
                
                if !self.verify_signature(&sig_bytes, &pubkey_bytes, context)? {
                    return Err(ScriptError::SigVerifyFailed);
                }
            }

            // Arithmetic
            OP_1ADD => {
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(a + 1))?;
            }
            
            OP_1SUB => {
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(a - 1))?;
            }
            
            OP_NEGATE => {
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(-a))?;
            }
            
            OP_ABS => {
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(a.abs()))?;
            }
            
            OP_NOT => {
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(if a == 0 { 1 } else { 0 }))?;
            }
            
            OP_0NOTEQUAL => {
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(if a != 0 { 1 } else { 0 }))?;
            }
            
            OP_ADD => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(a + b))?;
            }
            
            OP_SUB => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(a - b))?;
            }
            
            OP_BOOLAND => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(if a != 0 && b != 0 { 1 } else { 0 }))?;
            }
            
            OP_BOOLOR => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(if a != 0 || b != 0 { 1 } else { 0 }))?;
            }
            
            OP_NUMEQUAL => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(if a == b { 1 } else { 0 }))?;
            }
            
            OP_NUMEQUALVERIFY => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                if a != b {
                    return Err(ScriptError::VerifyFailed);
                }
            }
            
            OP_NUMNOTEQUAL => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(if a != b { 1 } else { 0 }))?;
            }
            
            OP_LESSTHAN => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(if a < b { 1 } else { 0 }))?;
            }
            
            OP_GREATERTHAN => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(if a > b { 1 } else { 0 }))?;
            }
            
            OP_LESSTHANOREQUAL => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(if a <= b { 1 } else { 0 }))?;
            }
            
            OP_GREATERTHANOREQUAL => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(if a >= b { 1 } else { 0 }))?;
            }
            
            OP_MIN => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(a.min(b)))?;
            }
            
            OP_MAX => {
                let b = Self::decode_num(&self.pop()?);
                let a = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(a.max(b)))?;
            }
            
            OP_WITHIN => {
                let max = Self::decode_num(&self.pop()?);
                let min = Self::decode_num(&self.pop()?);
                let x = Self::decode_num(&self.pop()?);
                self.push(Self::encode_num(if x >= min && x < max { 1 } else { 0 }))?;
            }

            // TODO: for now we just check format, actual validation needs block context)
            OP_CHECKLOCKTIMEVERIFY => {
                if self.stack.is_empty() {
                    return Err(ScriptError::StackUnderflow);
                }
                let locktime = Self::decode_num(self.peek()?);
                if locktime < 0 {
                    return Err(ScriptError::NegativeLocktime);
                }
                // we'd compare against tx locktime and block height/time
                // For now, just validate the format
            }
            
            OP_CHECKSEQUENCEVERIFY => {
                if self.stack.is_empty() {
                    return Err(ScriptError::StackUnderflow);
                }
                let sequence = Self::decode_num(self.peek()?);
                if sequence < 0 {
                    return Err(ScriptError::NegativeLocktime);
                }
                // In a real implementation, we'd compare against input sequence
            }

            OP_CODESEPARATOR => {
                // Code separator - affects signature checking
                // For simplicity, we just skip it
            }

            // Disabled opcodes
            0x7e..=0x81 | 0x83..=0x86 | 0x89..=0x8a | 0x8d..=0x8e | 0x95..=0x99 => {
                return Err(ScriptError::DisabledOpcode(op));
            }

            _ => {
                return Err(ScriptError::InvalidOpcode(op));
            }
        }
        Ok(())
    }

    /// Verify an ECDSA signature.
    fn verify_signature(
        &self,
        sig_bytes: &[u8],
        pubkey_bytes: &[u8],
        context: Option<&ScriptContext>,
    ) -> ScriptResult<bool> {
        // Need transaction context for signature verification
        let ctx = match context {
            Some(c) => c,
            None => return Ok(false), // Can't verify without context
        };

        // Empty signature or pubkey fails
        if sig_bytes.is_empty() || pubkey_bytes.is_empty() {
            return Ok(false);
        }

        // Parse signature (DER format + sighash byte at end)
        let sig = match Signature::decode(&sig_bytes[..sig_bytes.len().saturating_sub(1)]) {
            Some(s) => s,
            None => return Ok(false),
        };

        // Parse public key
        let pubkey = match PublicKey::decode(pubkey_bytes) {
            Some(pk) => pk,
            None => return Ok(false),
        };

        // Compute sighash
        let z = ctx.tx.sig_hash(ctx.input_index);

        // Verify signature
        Ok(verify_hash(&pubkey.point, &z, &sig))
    }

    /// Execute a script.
    pub fn execute(&mut self, script: &Script, context: Option<&ScriptContext>) -> ScriptResult<()> {
        for cmd in &script.cmds {
            match cmd {
                ScriptCmd::Data(data) => {
                    self.push(data.clone())?;
                }
                ScriptCmd::Op(op) => {
                    self.execute_op(*op, context)?;
                }
            }
        }
        Ok(())
    }

    /// Check if the script execution succeeded.
    /// 
    /// Returns true if the stack is non-empty and the top element is true.
    pub fn success(&self) -> bool {
        match self.stack.last() {
            Some(top) => Self::is_true(top),
            None => false,
        }
    }
}

// ============================================================================
// Script Evaluation
// ============================================================================

impl Script {
    /// combine this script with another (scriptSig + scriptPubKey).
    pub fn combine(&self, other: &Script) -> Script {
        let mut cmds = self.cmds.clone();
        cmds.extend(other.cmds.clone());
        Script { cmds }
    }

    /// evaluate this script with an optional transaction context.
    pub fn evaluate(&self, context: Option<&ScriptContext>) -> ScriptResult<bool> {
        let mut interpreter = ScriptInterpreter::new();
        interpreter.execute(self, context)?;
        Ok(interpreter.success())
    }

    /// evaluate a combined scriptSig + scriptPubKey.
    pub fn evaluate_p2pkh(
        script_sig: &Script,
        script_pubkey: &Script,
        tx: &Tx,
        input_index: usize,
    ) -> ScriptResult<bool> {
        let context = ScriptContext { tx, input_index };
        let combined = script_sig.combine(script_pubkey);
        combined.evaluate(Some(&context))
    }

    /// check if this script is a standard P2PKH scriptPubKey.
    pub fn is_p2pkh(&self) -> bool {
        self.cmds.len() == 5
            && matches!(self.cmds[0], ScriptCmd::Op(OP_DUP))
            && matches!(self.cmds[1], ScriptCmd::Op(OP_HASH160))
            && matches!(self.cmds[2], ScriptCmd::Data(ref d) if d.len() == 20)
            && matches!(self.cmds[3], ScriptCmd::Op(OP_EQUALVERIFY))
            && matches!(self.cmds[4], ScriptCmd::Op(OP_CHECKSIG))
    }

    /// check if this script is a standard P2SH scriptPubKey.
    pub fn is_p2sh(&self) -> bool {
        self.cmds.len() == 3
            && matches!(self.cmds[0], ScriptCmd::Op(OP_HASH160))
            && matches!(self.cmds[1], ScriptCmd::Data(ref d) if d.len() == 20)
            && matches!(self.cmds[2], ScriptCmd::Op(OP_EQUAL))
    }

    /// check if this script is an OP_RETURN (unspendable) output.
    pub fn is_op_return(&self) -> bool {
        !self.cmds.is_empty() && matches!(self.cmds[0], ScriptCmd::Op(OP_RETURN))
    }

    /// extract the pubkey hash from a P2PKH scriptPubKey.
    pub fn p2pkh_hash(&self) -> Option<Vec<u8>> {
        if self.is_p2pkh() {
            if let ScriptCmd::Data(hash) = &self.cmds[2] {
                return Some(hash.clone());
            }
        }
        None
    }
}

impl Tx {
    /// validate a transaction input using the script interpreter.
    pub fn validate_input(&self, input_index: usize) -> ScriptResult<bool> {
        use crate::transaction::TxFetcher;

        if input_index >= self.tx_ins.len() {
            return Err(ScriptError::StackUnderflow);
        }

        let tx_in = &self.tx_ins[input_index];
        
        // fetch the previous transaction to get the scriptPubKey
        let prev_tx = TxFetcher::fetch(&hex::encode(&tx_in.prev_tx), &tx_in.net);
        let prev_output = &prev_tx.tx_outs[tx_in.prev_index as usize];

        // evaluate the combined script
        Script::evaluate_p2pkh(
            &tx_in.script_sig,
            &prev_output.script_pubkey,
            self,
            input_index,
        )
    }

    /// validate all inputs in this transaction.
    pub fn validate(&self) -> ScriptResult<bool> {
        for i in 0..self.tx_ins.len() {
            if !self.validate_input(i)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

pub fn opcode_name(op: u8) -> &'static str {
    match op {
        OP_0 => "OP_0",
        OP_1NEGATE => "OP_1NEGATE",
        OP_1 => "OP_1",
        OP_2 => "OP_2",
        OP_3 => "OP_3",
        OP_4 => "OP_4",
        OP_5 => "OP_5",
        OP_6 => "OP_6",
        OP_7 => "OP_7",
        OP_8 => "OP_8",
        OP_9 => "OP_9",
        OP_10 => "OP_10",
        OP_11 => "OP_11",
        OP_12 => "OP_12",
        OP_13 => "OP_13",
        OP_14 => "OP_14",
        OP_15 => "OP_15",
        OP_16 => "OP_16",
        OP_NOP => "OP_NOP",
        OP_IF => "OP_IF",
        OP_NOTIF => "OP_NOTIF",
        OP_ELSE => "OP_ELSE",
        OP_ENDIF => "OP_ENDIF",
        OP_VERIFY => "OP_VERIFY",
        OP_RETURN => "OP_RETURN",
        OP_TOALTSTACK => "OP_TOALTSTACK",
        OP_FROMALTSTACK => "OP_FROMALTSTACK",
        OP_2DROP => "OP_2DROP",
        OP_2DUP => "OP_2DUP",
        OP_3DUP => "OP_3DUP",
        OP_2OVER => "OP_2OVER",
        OP_2ROT => "OP_2ROT",
        OP_2SWAP => "OP_2SWAP",
        OP_IFDUP => "OP_IFDUP",
        OP_DEPTH => "OP_DEPTH",
        OP_DROP => "OP_DROP",
        OP_DUP => "OP_DUP",
        OP_NIP => "OP_NIP",
        OP_OVER => "OP_OVER",
        OP_PICK => "OP_PICK",
        OP_ROLL => "OP_ROLL",
        OP_ROT => "OP_ROT",
        OP_SWAP => "OP_SWAP",
        OP_TUCK => "OP_TUCK",
        OP_SIZE => "OP_SIZE",
        OP_EQUAL => "OP_EQUAL",
        OP_EQUALVERIFY => "OP_EQUALVERIFY",
        OP_1ADD => "OP_1ADD",
        OP_1SUB => "OP_1SUB",
        OP_NEGATE => "OP_NEGATE",
        OP_ABS => "OP_ABS",
        OP_NOT => "OP_NOT",
        OP_0NOTEQUAL => "OP_0NOTEQUAL",
        OP_ADD => "OP_ADD",
        OP_SUB => "OP_SUB",
        OP_BOOLAND => "OP_BOOLAND",
        OP_BOOLOR => "OP_BOOLOR",
        OP_NUMEQUAL => "OP_NUMEQUAL",
        OP_NUMEQUALVERIFY => "OP_NUMEQUALVERIFY",
        OP_NUMNOTEQUAL => "OP_NUMNOTEQUAL",
        OP_LESSTHAN => "OP_LESSTHAN",
        OP_GREATERTHAN => "OP_GREATERTHAN",
        OP_LESSTHANOREQUAL => "OP_LESSTHANOREQUAL",
        OP_GREATERTHANOREQUAL => "OP_GREATERTHANOREQUAL",
        OP_MIN => "OP_MIN",
        OP_MAX => "OP_MAX",
        OP_WITHIN => "OP_WITHIN",
        OP_RIPEMD160 => "OP_RIPEMD160",
        OP_SHA1 => "OP_SHA1",
        OP_SHA256 => "OP_SHA256",
        OP_HASH160 => "OP_HASH160",
        OP_HASH256 => "OP_HASH256",
        OP_CODESEPARATOR => "OP_CODESEPARATOR",
        OP_CHECKSIG => "OP_CHECKSIG",
        OP_CHECKSIGVERIFY => "OP_CHECKSIGVERIFY",
        OP_CHECKMULTISIG => "OP_CHECKMULTISIG",
        OP_CHECKMULTISIGVERIFY => "OP_CHECKMULTISIGVERIFY",
        OP_CHECKLOCKTIMEVERIFY => "OP_CHECKLOCKTIMEVERIFY",
        OP_CHECKSEQUENCEVERIFY => "OP_CHECKSEQUENCEVERIFY",
        _ => "OP_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::BITCOIN;
    use crate::keys::PublicKey;
    use crate::transaction::{Script, ScriptCmd, TxFetcher, TxIn, TxOut};
    use num_bigint::BigInt;
    use num_traits::Num;

    #[test]
    fn test_op_dup() {
        let mut interpreter = ScriptInterpreter::new();
        interpreter.push(vec![1, 2, 3]).unwrap();
        interpreter.execute_op(OP_DUP, None).unwrap();
        
        assert_eq!(interpreter.stack.len(), 2);
        assert_eq!(interpreter.stack[0], vec![1, 2, 3]);
        assert_eq!(interpreter.stack[1], vec![1, 2, 3]);
    }

    #[test]
    fn test_op_hash160() {
        let mut interpreter = ScriptInterpreter::new();
        let data = b"test data";
        interpreter.push(data.to_vec()).unwrap();
        interpreter.execute_op(OP_HASH160, None).unwrap();
        
        assert_eq!(interpreter.stack.len(), 1);
        // HASH160 produces 20-byte output
        assert_eq!(interpreter.stack[0].len(), 20);
        
        // Verify it matches manual RIPEMD160(SHA256(data))
        let expected = ripemd160(&sha256(data));
        assert_eq!(interpreter.stack[0], expected);
    }

    #[test]
    fn test_op_equalverify_success() {
        let mut interpreter = ScriptInterpreter::new();
        interpreter.push(vec![1, 2, 3]).unwrap();
        interpreter.push(vec![1, 2, 3]).unwrap();
        
        let result = interpreter.execute_op(OP_EQUALVERIFY, None);
        assert!(result.is_ok());
        assert!(interpreter.stack.is_empty());
    }

    #[test]
    fn test_op_equalverify_failure() {
        let mut interpreter = ScriptInterpreter::new();
        interpreter.push(vec![1, 2, 3]).unwrap();
        interpreter.push(vec![4, 5, 6]).unwrap();
        
        let result = interpreter.execute_op(OP_EQUALVERIFY, None);
        assert!(matches!(result, Err(ScriptError::EqualVerifyFailed)));
    }

    #[test]
    fn test_op_equal() {
        let mut interpreter = ScriptInterpreter::new();
        interpreter.push(vec![1, 2, 3]).unwrap();
        interpreter.push(vec![1, 2, 3]).unwrap();
        interpreter.execute_op(OP_EQUAL, None).unwrap();
        
        assert_eq!(interpreter.stack.len(), 1);
        assert_eq!(interpreter.stack[0], vec![1]); // true
    }

    #[test]
    fn test_number_encoding() {
        // Test encode/decode roundtrip
        for n in [-1000i64, -1, 0, 1, 127, 128, 255, 256, 1000] {
            let encoded = ScriptInterpreter::encode_num(n);
            let decoded = ScriptInterpreter::decode_num(&encoded);
            assert_eq!(n, decoded, "Failed for n={}", n);
        }
    }

    #[test]
    fn test_op_add() {
        let mut interpreter = ScriptInterpreter::new();
        interpreter.push(ScriptInterpreter::encode_num(5)).unwrap();
        interpreter.push(ScriptInterpreter::encode_num(3)).unwrap();
        interpreter.execute_op(OP_ADD, None).unwrap();
        
        let result = ScriptInterpreter::decode_num(&interpreter.stack[0]);
        assert_eq!(result, 8);
    }

    #[test]
    fn test_op_sub() {
        let mut interpreter = ScriptInterpreter::new();
        interpreter.push(ScriptInterpreter::encode_num(10)).unwrap();
        interpreter.push(ScriptInterpreter::encode_num(3)).unwrap();
        interpreter.execute_op(OP_SUB, None).unwrap();
        
        let result = ScriptInterpreter::decode_num(&interpreter.stack[0]);
        assert_eq!(result, 7);
    }

    #[test]
    fn test_small_numbers() {
        let mut interpreter = ScriptInterpreter::new();
        
        // Test OP_1 through OP_16
        for i in 1..=16 {
            interpreter.execute_op(OP_1 + (i - 1) as u8, None).unwrap();
        }
        
        assert_eq!(interpreter.stack.len(), 16);
        for (i, item) in interpreter.stack.iter().enumerate() {
            let n = ScriptInterpreter::decode_num(item);
            assert_eq!(n, (i + 1) as i64);
        }
    }

    #[test]
    fn test_op_verify_success() {
        let mut interpreter = ScriptInterpreter::new();
        interpreter.push(vec![1]).unwrap(); // true
        
        let result = interpreter.execute_op(OP_VERIFY, None);
        assert!(result.is_ok());
        assert!(interpreter.stack.is_empty());
    }

    #[test]
    fn test_op_verify_failure() {
        let mut interpreter = ScriptInterpreter::new();
        interpreter.push(vec![]).unwrap(); // false (empty = 0)
        
        let result = interpreter.execute_op(OP_VERIFY, None);
        assert!(matches!(result, Err(ScriptError::VerifyFailed)));
    }

    #[test]
    fn test_op_return() {
        let mut interpreter = ScriptInterpreter::new();
        let result = interpreter.execute_op(OP_RETURN, None);
        assert!(matches!(result, Err(ScriptError::OpReturn)));
    }

    #[test]
    fn test_is_true() {
        // Empty is false
        assert!(!ScriptInterpreter::is_true(&[]));
        
        // Zero is false
        assert!(!ScriptInterpreter::is_true(&[0]));
        assert!(!ScriptInterpreter::is_true(&[0, 0]));
        
        // Negative zero is false
        assert!(!ScriptInterpreter::is_true(&[0x80]));
        
        // Non-zero is true
        assert!(ScriptInterpreter::is_true(&[1]));
        assert!(ScriptInterpreter::is_true(&[0, 1]));
    }

    #[test]
    fn test_script_p2pkh_detection() {
        let pubkey_hash = vec![0xab; 20];
        let script = Script::p2pkh(&pubkey_hash);
        
        assert!(script.is_p2pkh());
        assert!(!script.is_p2sh());
        assert!(!script.is_op_return());
        
        assert_eq!(script.p2pkh_hash(), Some(pubkey_hash));
    }

    #[test]
    fn test_script_op_return_detection() {
        let script = Script {
            cmds: vec![
                ScriptCmd::Op(OP_RETURN),
                ScriptCmd::Data(b"hello".to_vec()),
            ],
        };
        
        assert!(script.is_op_return());
        assert!(!script.is_p2pkh());
    }

    #[test]
    fn test_stack_operations() {
        let mut interpreter = ScriptInterpreter::new();
        
        // Test SWAP
        interpreter.push(vec![1]).unwrap();
        interpreter.push(vec![2]).unwrap();
        interpreter.execute_op(OP_SWAP, None).unwrap();
        assert_eq!(interpreter.stack, vec![vec![2], vec![1]]);
        
        // Test DROP
        interpreter.execute_op(OP_DROP, None).unwrap();
        assert_eq!(interpreter.stack, vec![vec![2]]);
        
        // Test DUP
        interpreter.execute_op(OP_DUP, None).unwrap();
        assert_eq!(interpreter.stack, vec![vec![2], vec![2]]);
    }

    #[test]
    fn test_altstack() {
        let mut interpreter = ScriptInterpreter::new();
        
        interpreter.push(vec![1, 2, 3]).unwrap();
        interpreter.execute_op(OP_TOALTSTACK, None).unwrap();
        
        assert!(interpreter.stack.is_empty());
        assert_eq!(interpreter.alt_stack.len(), 1);
        
        interpreter.execute_op(OP_FROMALTSTACK, None).unwrap();
        
        assert_eq!(interpreter.stack, vec![vec![1, 2, 3]]);
        assert!(interpreter.alt_stack.is_empty());
    }

    /// Helper to create a fake coinbase-like input for test transactions
    fn fake_coinbase_input() -> TxIn {
        TxIn {
            prev_tx: vec![0u8; 32],
            prev_index: 0xffffffff,
            script_sig: Script {
                cmds: vec![ScriptCmd::Data(vec![0x04, 0xff, 0xff, 0x00, 0x1d])],
            },
            sequence: 0xffffffff,
            witness: None,
            net: "main".to_string(),
        }
    }

    #[test]
    fn test_p2pkh_script_execution() {
        // Use a known private key
        let secret_key = BigInt::from_str_radix(
            "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD",
            16,
        )
        .unwrap();

        // Create the public key and get its hash for P2PKH
        let pk = PublicKey::from_sk(&secret_key, &BITCOIN.generator.g);
        let pkb_hash = pk.encode(true, true); // compressed, hash160

        // Create a fake "previous transaction" that pays to our public key
        let prev_tx_out = TxOut {
            amount: 100_000_000,
            script_pubkey: Script::p2pkh(&pkb_hash),
        };

        let fake_prev_tx = Tx {
            version: 1,
            tx_ins: vec![fake_coinbase_input()],
            tx_outs: vec![prev_tx_out],
            locktime: 0,
            segwit: false,
        };

        // Cache the fake previous tx
        let prev_txid = fake_prev_tx.txid_bytes();
        TxFetcher::cache_tx(&hex::encode(&prev_txid), fake_prev_tx.encode(false, None));

        // Create an input spending from our fake previous tx
        let tx_in = TxIn {
            prev_tx: prev_txid,
            prev_index: 0,
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: None,
            net: "main".to_string(),
        };

        // Create an output
        let target_pkb_hash = hex::decode("7a986d955c6e0cb35d446a89d3f56100f4d7f678").unwrap();
        let tx_out = TxOut {
            amount: 99_990_000,
            script_pubkey: Script::p2pkh(&target_pkb_hash),
        };

        // Create the transaction
        let mut tx = Tx {
            version: 1,
            tx_ins: vec![tx_in],
            tx_outs: vec![tx_out],
            locktime: 0,
            segwit: false,
        };

        // Sign the input
        tx.sign_input(0, &secret_key, true);

        // Validate using the script interpreter
        let result = tx.validate_input(0);
        assert!(result.is_ok(), "Script execution should succeed");
        assert!(result.unwrap(), "P2PKH validation should pass");
    }

    #[test]
    fn test_p2pkh_wrong_signature_fails() {
        // Two different keys
        let secret_key1 = BigInt::from_str_radix(
            "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD",
            16,
        )
        .unwrap();
        let secret_key2 = BigInt::from(999999);

        // Create public key for key1
        let pk1 = PublicKey::from_sk(&secret_key1, &BITCOIN.generator.g);
        let pkb_hash1 = pk1.encode(true, true);

        // Create a fake previous tx that pays to key1
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

        // Create transaction spending the output
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

        // Sign with wrong key (key2 instead of key1)
        tx.sign_input(0, &secret_key2, true);

        // Validation should fail because pubkey hash won't match
        // This causes OP_EQUALVERIFY to fail, which returns an error
        let result = tx.validate_input(0);
        // Either an error (EqualVerifyFailed) or Ok(false) is acceptable
        match result {
            Ok(success) => assert!(!success, "Validation should fail with wrong key"),
            Err(ScriptError::EqualVerifyFailed) => {} // This is expected - pubkey hash mismatch
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_simple_script_evaluation() {
        // Test a simple script: 2 + 3 = 5
        let script = Script {
            cmds: vec![
                ScriptCmd::Op(OP_2),      // Push 2
                ScriptCmd::Op(OP_3),      // Push 3
                ScriptCmd::Op(OP_ADD),    // 2 + 3 = 5
                ScriptCmd::Op(OP_5),      // Push 5
                ScriptCmd::Op(OP_EQUAL),  // Compare: 5 == 5
            ],
        };

        let result = script.evaluate(None);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_hash_operations() {
        let mut interpreter = ScriptInterpreter::new();
        let data = b"hello";
        
        // Test SHA256
        interpreter.push(data.to_vec()).unwrap();
        interpreter.execute_op(OP_SHA256, None).unwrap();
        assert_eq!(interpreter.stack[0].len(), 32);
        
        // Test HASH256 (double SHA256)
        interpreter.stack.clear();
        interpreter.push(data.to_vec()).unwrap();
        interpreter.execute_op(OP_HASH256, None).unwrap();
        assert_eq!(interpreter.stack[0].len(), 32);
        let expected = sha256(&sha256(data));
        assert_eq!(interpreter.stack[0], expected);
    }

    #[test]
    fn test_comparison_ops() {
        let mut interpreter = ScriptInterpreter::new();
        
        // Test LESSTHAN: 3 < 5
        interpreter.push(ScriptInterpreter::encode_num(3)).unwrap();
        interpreter.push(ScriptInterpreter::encode_num(5)).unwrap();
        interpreter.execute_op(OP_LESSTHAN, None).unwrap();
        assert_eq!(ScriptInterpreter::decode_num(&interpreter.pop().unwrap()), 1);
        
        // Test GREATERTHAN: 5 > 3
        interpreter.push(ScriptInterpreter::encode_num(5)).unwrap();
        interpreter.push(ScriptInterpreter::encode_num(3)).unwrap();
        interpreter.execute_op(OP_GREATERTHAN, None).unwrap();
        assert_eq!(ScriptInterpreter::decode_num(&interpreter.pop().unwrap()), 1);
    }
}

