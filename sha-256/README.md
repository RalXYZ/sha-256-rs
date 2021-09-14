# Assignment: SHA-256

## Problem Description
The SHA-256 algorithm is one flavor of SHA-2 (Secure Hash Algorithm 2), which was created by the National Security Agency in 2001 as a successor to SHA-1. SHA-256 is a patented cryptographic hash function that outputs a value that is 256 bits long.  

In this assginment, we are required to implement a SHA-256 hashing algorithm. The programming language used for coding is not specified. After implementation, we are required to test the efficiency of this algorithm, by checking how long it takes for SHA-256 to find a hashing result with 6, 8 and 10 concecutive prefix zero bits.  


## Algorithm Implementation
Rust is used to implement SHA-256 algorithm.  

### Trait
`Sha256` trait has been implemented for `Vec<u8>`:  

```rust
pub trait Sha256 {
    fn do_hash(&self) -> [u8; 32];
    fn process_64_byte(input: [u8; 64], h: &mut [u32; 8]);
}
```

Function `do_hash` is the entrance of the whole algorithm. Function `process_64_byte` is called by `do_hash`, and it performs the algrithm, update the hash values for each 512 bit block.  

### Constants

SHA-256 defines 64 constants, which are the first 32 bits of the *fractional parts* of the cube roots of the first 64 primes. The initialize array of round constants consists of the 64 constants mentioned above.  

```rust
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
```

### `do_hash` procedure

#### Initialize array of round constants
The first 32 bits of the fractional parts of the square roots of the first 8 primes $2..19$.  
```rust
let mut h: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
```

#### Pre-processing
Assume we begin with the original message of length $L$ bits. The thing to do first is to append a single '1' bit to the origenal message. Then, append $K$ '0' bits, where $K$ is the minimum number $\ge 0$ such that $L + 1 + K + 64$ is a multiple of 512. After that, append L as a 64-bit **big-endian** integer, making the total post-processed length a multiple of 512 bits, such that the bits in the message are $L 1 00..<K\ 0's>..00 <L\ as\ 64\ bit\ integer> = k\times512$ total bits.  

```rust
let input_len = self.len();
let mut data: Vec<u8> = self.to_vec();
    data.push(0b1000_0000);
if data.len().rem(64).lt(&56) {
    data.append(&mut vec![0u8; 56 - (data.len().rem(64))]);
} else {
    data.append(&mut vec![0u8; 64 + 56 - (data.len().rem(64))]);
}
data.extend_from_slice(&(input_len * 8).to_be_bytes());
```

#### Process the message in successive 512-bit chunks
Firstly, break message into 512-bit chunks. Then, iterate these chunks, for each chunk, call `process_64_byte`.  

```rust
let data: Vec<[u8; 64]> = (0..(data.len().div(64)))
    .map(|x| {
        let mut temp: [u8; 64] = [0; 64];
        temp.copy_from_slice(&data[x * 64..x * 64 + 64]);
        temp
    })
.collect();
data.iter().for_each(|x| Self::process_64_byte(*x, &mut h));
```

### `process_64_byte` procedure

#### Aggregate and copy
Create a 64-entry message schedule array $w[0..63]$ of 32-bit words. The initial values in $w[0..63]$ don't matter, so many implementations zero them here. Copy the aggregation result to $w[0..15]$. 
```rust
let w: [[u8; 4]; 16] = input.as_chunks::<4>().0.try_into().unwrap();
let temp = w.map(u32::from_be_bytes);
let mut w: [u32; 64] = [0; 64];
w[0..16].copy_from_slice(&temp);
```

#### Extend words
Extend the first 16 words into the remaining 48 words $w[16..63]$ of the message schedule array.  
```rust
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
```

#### Initialize working variables
Initialize working variables to current hash value.  

```rust
let mut work_var: [u32; 8] = [0; 8];
work_var.copy_from_slice(h);
```

#### Compression function main loop

```rust
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
```

#### Add the compressed chunk to the current hash value

```rust
for y in 0..8 {
    h[y] = h[y].wrapping_add(work_var[y]);
}
```


## Testing

Here is a table, which contains the time elapse of finding $x$ consecutive prefix zeros.  

| consecutive prefix zeros | test 1         | test 2         | test 3       | test 4         | average        |
| ------------------------ | -------------- | -------------- | ------------ | -------------- | -------------- |
| 6                        | $929 \mu s$    | $1086 \mu s$   | $852 \mu s$  | $663 \mu s$    | $883 \mu s$    |
| 8                        | $3336 \mu s$   | $3476 \mu s$   | $3893 \mu s$ | $4760 \mu s$   | $3866 \mu s$   |
| 10                       | $22,226 \mu s$ | $30,303 \mu s$ | $8878 \mu s$ | $54,949 \mu s$ | $27,704 \mu s$ |

