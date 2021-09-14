#![feature(slice_as_chunks)]

use std::convert::TryInto;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct Sha256 {

}

impl Default for Sha256 {
    fn default() -> Self {
        todo!()
    }
}

impl Sha256 {
    pub fn do_hash(&mut self, input: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];

        let input_len = input.len();
        let mut pending: [u8; 64] = [0; 64];
        pending[..input_len]
            .copy_from_slice(&input); // FIXME: len greater than 64
        pending[input_len] = 0b1000_0000;
        pending[64 - 8..64]
            .copy_from_slice(
                &(input_len * 8)
                    .to_be_bytes()
            );
        Self::process_64_byte(pending, &mut h);

        let mut result: [u8; 32] = [0; 32];

        for x in 0..8 {
            result[x * 4 .. x * 4 + 4].copy_from_slice(&h[x].to_be_bytes());
        }

        result
    }

    fn process_64_byte(input: [u8; 64], h: &mut [u32; 8]) {
        let w: [[u8; 4]; 16] = input.
            as_chunks::<4>()
            .0
            .try_into()
            .unwrap();
        let temp = w
            .map(u32::from_be_bytes);
        let mut w: [u32; 64] = [0; 64];
        w[0..16].copy_from_slice(&temp);

        for x in 16..64 {
            let s0 = Self::right_rotate(w[x - 15], 7)
                ^ Self::right_rotate(w[x - 15], 18) ^ (w[x - 15] >> 3);
            let s1 = Self::right_rotate(w[x - 2], 17)
                ^ Self::right_rotate(w[x - 2], 19) ^ (w[x - 2] >> 10);
            w[x] = w[x - 16]
                .wrapping_add(s0)
                .wrapping_add(w[x - 7])
                .wrapping_add(s1);
        }

        let mut work_var: [u32; 8] = [0; 8]; // a b c d e f g h
        work_var.copy_from_slice(h);
        for y in 0..64 {
            let s0 =
                Self::right_rotate(work_var[0], 2)
                    ^ Self::right_rotate(work_var[0], 13)
                    ^ Self::right_rotate(work_var[0], 22);
            let maj =
                (work_var[0] & work_var[1])
                    ^ (work_var[0] & work_var[2])
                    ^ (work_var[1] & work_var[2]);
            let temp2 = s0.wrapping_add(maj);
            let s1 = Self::right_rotate(work_var[4], 6)
                ^ Self::right_rotate(work_var[4], 11)
                ^ Self::right_rotate(work_var[4], 25);
            let ch = (work_var[4] & work_var[5])
                ^ ((!work_var[4]) & work_var[6]);
            let temp1 = work_var[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[y])
                .wrapping_add(w[y]);
            for z in (1..8).rev() {
                work_var[z] = work_var[z - 1];
            }
            work_var[0] = temp1.wrapping_add(temp2);
            work_var[4] = work_var[4].wrapping_add(temp1);
        }
        for y in 0..8 {
            h[y] = h[y].wrapping_add(work_var[y]);
        }
    }

    fn right_rotate(n: u32, d: u32) -> u32 {
        (n >> d) | (n << (32 - d))
    }
}

#[cfg(test)]

mod tests {
    use crate::Sha256;

    #[test]
    fn short_sha_256() {
        let mut test = Sha256{};
        assert_eq!(
            test
                .do_hash(b"abc")
                .to_vec(),
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap()
        );
        assert_eq!(
            test
                .do_hash(b"blockchain")
                .to_vec(),
            hex::decode("ef7797e13d3a75526946a3bcf00daec9fc9c9c4d51ddc7cc5df888f74dd434d1")
                .unwrap()
        );
    }

    #[test]
    fn long_sha_256() {
        let mut test = Sha256{};
        assert_eq!(
            test
                .do_hash(b"The quick brown fox jumps over the lazy dog")
                .to_vec(),
            hex::decode("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
                .unwrap()
        );
        assert_eq!(
            test
                .do_hash(b"It is a truth universally acknowledged, that a single man in possession of a good fortune, must be in want of a wife.")
                .to_vec(),
            hex::decode("ff3583336f59ddbfb6b202e15e9ed7fa05f3b6da8e159cd237af89fc02e5932e")
                .unwrap()
        );
    }
}
