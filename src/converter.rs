use crate::Q;

// k denotes the length of f_arr
pub(crate) fn byte_encode_mult(k: usize, f_arr: &Vec<[u16; 256]>, d: u8) -> Vec<u8> {
    debug_assert!(f_arr.len() == k, "Input array must have k elements");
    debug_assert!(f_arr[0].len() == 256, "Input elements array must have 256 elements");
    debug_assert!((1..=12).contains(&d), "Bit-width d must be between 1 and 12");

    let output_len = 32 * (d as usize) * k;
    let mut output = Vec::with_capacity(output_len);
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for i in 0..k {
        for &val in f_arr[i].iter() {
            let a = (val & ((1 << d) - 1)) as u64; // ensure only d bits
            buffer |= a << bits_in_buffer;
            bits_in_buffer += d;
    
            while bits_in_buffer >= 8 {
                output.push((buffer & 0xFF) as u8);
                buffer >>= 8;
                bits_in_buffer -= 8;
            }
        }
    }
    if bits_in_buffer > 0 {
        output.push(buffer as u8);
    }

    debug_assert!(output.len() == output_len, "Output length should be exactly 32 * d * k");
    output
}

// byte_encode for single byte arrays
pub(crate) fn byte_encode(f_arr: &[u16; 256], d: u8) -> Vec<u8> {
    debug_assert!((1..=12).contains(&d), "Bit-width d must be between 1 and 12");

    let mut output = Vec::with_capacity(32 * (d as usize));
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &val in f_arr.iter() {
        let a = (val & ((1 << d) - 1)) as u64; // ensure only d bits
        buffer |= a << bits_in_buffer;
        bits_in_buffer += d;

        while bits_in_buffer >= 8 {
            output.push((buffer & 0xFF) as u8);
            buffer >>= 8;
            bits_in_buffer -= 8;
        }
    }
    if bits_in_buffer > 0 {
        output.push(buffer as u8);
    }

    debug_assert!(output.len() == 32 * (d as usize), "Output length should be exactly 32 * d");
    output
}

// byte_decode used for single byte arrays
pub(crate) fn byte_decode(bytes: &[u8], d: u8) -> [u16; 256] {
    debug_assert!((1..=12).contains(&d), "Bit-width d must be between 1 and 12");
    debug_assert!(bytes.len() == 32 * (d as usize), "Input byte array must be of length 32 * d");

    let mut output = [0u16; 256];
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;
    let mut byte_idx = 0;

    for i in 0..256 {
        while bits_in_buffer < d {
            buffer |= (bytes[byte_idx] as u64) << bits_in_buffer;
            bits_in_buffer += 8;
            byte_idx += 1;
        }

        let mut val = (buffer & ((1 << d) - 1)) as u16;
        buffer >>= d;
        bits_in_buffer -= d;

        if d == 12 {
            val %= Q;
        }

        output[i] = val;
    }
    

    output
}

pub(crate) fn compress(d: u8, f: &[u16; 256]) -> [u16; 256] {
    let mut result = [0u16; 256];
    let two_pow_d = 1 << d;
    for i in 0..256 {
        let scaled = (f[i] as u32 * two_pow_d as u32 + Q as u32 / 2) / Q as u32;
        result[i] = (scaled % two_pow_d) as u16;
    }
    result
}

pub(crate) fn decompress(d: u8, k: &[u16; 256]) -> [u16; 256] {
    let mut result: [u16; 256] = [0u16; 256];
    let two_pow_d = 1 << d;
    for i in 0..256 {
        result[i] = ((k[i] as u32 * Q as u32 + two_pow_d as u32 / 2) / two_pow_d) as u16;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*; // import everything from the parent module

    #[test]
    fn test_byte_encode_mult_decode_roundtrip() {
        let k: usize = 3;
        let d = 10;
        let input: Vec<[u16; 256]> = (0..k).map(|block| core::array::from_fn(|i| (block * 256 + i) as u16 % (1 << d))).collect();

        let encoded = byte_encode_mult(k, &input, d);
        let mut decoded = Vec::with_capacity(k);
        for i in 0..k {
            decoded.push(byte_decode(&encoded[32 * (d as usize) * i .. 32 * (d as usize) * (i + 1)], d));
        }
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_byte_encode_decode_roundtrip() {
        let d: u8 = 7;
        let input: [u16; 256] = core::array::from_fn(|i| (i * 9 + i % 17) as u16 % (1 << d));

        let encoded = byte_encode(&input, d);
        let decoded = byte_decode(&encoded, d);
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_byte_encode_decode_d12_modq() {
        let k: usize = 3;
        let d = 10;
        let input: Vec<[u16; 256]> = (0..k).map(|block| core::array::from_fn(|i| (block * 256 + i) as u16 % (1 << d))).collect();
        let encoded = byte_encode_mult(k, &input, d);
        let mut decoded = Vec::with_capacity(k);
        for i in 0..k {
            decoded.push(byte_decode(&encoded[32 * (d as usize) * i .. 32 * (d as usize) * (i + 1)], d));
        }
        let expected: Vec<[u16; 256]> = input.iter().map(| poly | poly.map(|x| x % 3329)).collect();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_compress_decompress_roundtrip() {
        let d = 12;
        let all_values: Vec<u16> = (0..3329).collect();
        for chunk in all_values.chunks(256) {
            let mut input = [0u16; 256];
            for (i, &val) in chunk.iter().enumerate() {
                input[i] = val;
            }
            let compressed = compress(d, &input);
            for elem in compressed {
                println!("{}", elem);
            }
            let decompressed = decompress(d, &compressed);

            assert_eq!(decompressed, input);
        }
    }
}