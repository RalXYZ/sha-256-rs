#![feature(slice_as_chunks)]

use std::convert::TryInto;
use std::ops::{Div, Rem};

// Initialize array of round constants:
// (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
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

pub trait Sha256 {
    fn do_hash(&self) -> [u8; 32];
    fn process_64_byte(input: [u8; 64], h: &mut [u32; 8]);
}

impl Sha256 for Vec<u8> {
    fn do_hash(&self) -> [u8; 32] {

        // Initialize hash values:
        // (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        // Pre-processing (Padding):
        // begin with the original message of length L bits
        // append a single '1' bit
        // append K '0' bits, where K is the minimum number >= 0
        // such that L + 1 + K + 64 is a multiple of 512
        // append L as a 64-bit big-endian integer,
        // making the total post-processed length a multiple of 512 bits
        // such that the bits in the message are
        // L 1 00..<K 0's>..00 <L as 64 bit integer> = k*512 total bits
        let input_len = self.len();
        let mut data: Vec<u8> = self.to_vec();
        data.push(0b1000_0000);
        if data.len().rem(64).lt(&56) {
            data.append(&mut vec![0u8; 56 - (data.len().rem(64))]);
        } else {
            data.append(&mut vec![0u8; 64 + 56 - (data.len().rem(64))]);
        }
        data.extend_from_slice(&(input_len * 8).to_be_bytes());

        // Process the message in successive 512-bit chunks:
        // break message into 512-bit chunks
        let data: Vec<[u8; 64]> = (0..(data.len().div(64)))
            .map(|x| {
                let mut temp: [u8; 64] = [0; 64];
                temp.copy_from_slice(&data[x * 64..x * 64 + 64]);
                temp
            })
            .collect();

        // for each chunk
        data.iter().for_each(|x| Self::process_64_byte(*x, &mut h));

        let mut result: [u8; 32] = [0; 32];

        for x in 0..8 {
            result[x * 4..x * 4 + 4].copy_from_slice(&h[x].to_be_bytes());
        }

        result
    }

    fn process_64_byte(input: [u8; 64], h: &mut [u32; 8]) {

        // create a 64-entry message schedule array w[0..64] of 32-bit words
        // (The initial values in w[0..64] don't matter, so many implementations zero them here)
        // copy chunk into first 16 words w[0..16] of the message schedule array
        let w: [[u8; 4]; 16] = input.as_chunks::<4>().0.try_into().unwrap();
        let temp = w.map(u32::from_be_bytes);
        let mut w: [u32; 64] = [0; 64];
        w[0..16].copy_from_slice(&temp);

        // Extend the first 16 words into the remaining
        // 48 words w[16..64] of the message schedule array:
        for x in 16..64 {
            let s0 = w[x - 15].rotate_right(7)
                ^ w[x - 15].rotate_right(18)
                ^ (w[x - 15] >> 3);
            let s1 = w[x - 2].rotate_right(17)
                ^ w[x - 2].rotate_right(19)
                ^ (w[x - 2] >> 10);
            w[x] = w[x - 16]
                .wrapping_add(s0)
                .wrapping_add(w[x - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables to current hash value:
        let mut work_var: [u32; 8] = [0; 8];
        work_var.copy_from_slice(h);

        // Compression function main loop:
        for y in 0..64 {
            let s0 = work_var[0].rotate_right(2)
                ^ work_var[0].rotate_right(13)
                ^ work_var[0].rotate_right(22);
            let maj = (work_var[0] & work_var[1])
                ^ (work_var[0] & work_var[2])
                ^ (work_var[1] & work_var[2]);
            let temp2 = s0.wrapping_add(maj);
            let s1 = work_var[4].rotate_right(6)
                ^ work_var[4].rotate_right(11)
                ^ work_var[4].rotate_right(25);
            let ch = (work_var[4] & work_var[5]) ^ ((!work_var[4]) & work_var[6]);
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

        // Add the compressed chunk to the current hash value:
        for y in 0..8 {
            h[y] = h[y].wrapping_add(work_var[y]);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Sha256;
    use std::time::Instant;
    use rayon::prelude::*;
    use core::ops::ControlFlow;

    struct NumGen {
        data: Vec<u8>
    }


    impl Iterator for NumGen {
        type Item = Vec<u8>;

        fn next(&mut self) -> Option<Vec<u8>> {
            self.data.iter_mut().try_for_each(|x| {
                *x = x.wrapping_add(1);
                if *x != 0 {
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            });

            Some(self.data.clone())
        }
    }


    #[test]
    fn short_sha_256() {
        assert_eq!(
            b"abc".to_vec().do_hash().to_vec(),
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap()
        );
        assert_eq!(
            b"blockchain".to_vec().do_hash().to_vec(),
            hex::decode("ef7797e13d3a75526946a3bcf00daec9fc9c9c4d51ddc7cc5df888f74dd434d1")
                .unwrap()
        );
    }

    #[test]
    fn long_sha_256() {
        assert_eq!(
            b"The quick brown fox jumps over the lazy dog"
                .to_vec()
                .do_hash()
                .to_vec(),
            hex::decode("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
                .unwrap()
        );
        assert_eq!(
            b"It is a truth universally acknowledged, that a single man in possession of a good fortune, must be in want of a wife."
                .to_vec()
                .do_hash()
                .to_vec(),
            hex::decode("ff3583336f59ddbfb6b202e15e9ed7fa05f3b6da8e159cd237af89fc02e5932e")
                .unwrap()
        );
    }

    #[test]
    fn test_consecutive_zeros() {
        let start = Instant::now();
        let iter = NumGen{data: vec![0; 32]};

        let result = (0..).par_bridge()
            .map(|_x| (0..32)
                .map(|_|  rand::random::<u8>())
                .collect::<Vec<u8>>()
            )
            .map(|x| x.do_hash())
            .find_any(|x| x[0] == 0 && x[1] == 0 && x[2] == 0 && x[3] & 0b1111_1100 == 0);
        dbg!(result.unwrap());
        dbg!(&iter.data.clone());
        println!("find consecutive prefix 0 cost: {:?} us", start.elapsed().as_micros());
    }
}
