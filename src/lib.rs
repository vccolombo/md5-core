pub mod md5_core {
    use std::num::Wrapping;

    pub struct Md5 {
        buffer: Vec<u8>,
        length: u64,
        a0: u32,
        b0: u32,
        c0: u32,
        d0: u32,
    }

    impl Md5 {
        const PRECOMPUTED_TABLE: [u32; 64] = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
            0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
            0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
            0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
            0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
            0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
            0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
            0xeb86d391,
        ];

        const SHIFT_TABLE: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];

        pub fn new() -> Self {
            Self {
                buffer: Vec::new(),
                length: 0,
                a0: 0x67452301,
                b0: 0xEFCDAB89,
                c0: 0x98BADCFE,
                d0: 0x10325476,
            }
        }

        /// Returns a new Md5 object with the updated state of the md5 calculation
        /// It means that this function is pure (no mutations)
        ///
        /// # Example
        ///
        /// ```
        /// use md5_core::md5_core::Md5;
        ///
        /// let mut md5 = Md5::new();
        /// md5 = md5.consume(b"hello");
        /// ```
        pub fn consume(&self, data: &[u8]) -> Self {
            let mut buffer = [&self.buffer, data].concat();
            let mut a0 = self.a0;
            let mut b0 = self.b0;
            let mut c0 = self.c0;
            let mut d0 = self.d0;

            while buffer.len() >= 64 {
                let digested = Md5::calculate_chunks(&buffer[..64], a0, b0, c0, d0);
                a0 = ((digested >> 96) & 0xffffffff).try_into().unwrap();
                a0 = a0.to_be();
                b0 = ((digested >> 64) & 0xffffffff).try_into().unwrap();
                b0 = b0.to_be();
                c0 = ((digested >> 32) & 0xffffffff).try_into().unwrap();
                c0 = c0.to_be();
                d0 = ((digested >> 00) & 0xffffffff).try_into().unwrap();
                d0 = d0.to_be();
                buffer = buffer[64..].to_vec();
            }

            Self {
                buffer,
                length: self.length + (data.len() as u64),
                a0,
                b0,
                c0,
                d0,
            }
        }

        /// # Example
        ///
        /// ```
        /// use md5_core::md5_core::Md5;
        ///
        /// let mut md5 = Md5::new();
        /// md5 = md5.consume(b"hello");
        /// md5 = md5.consume(b"world");
        /// assert_eq!(md5.digest(), 0xfc5e038d38a57032085441e7fe7010b0);
        /// ```
        pub fn digest(&self) -> u128 {
            let preprocessed = Self::preprocess(&self.buffer, self.length * 8);

            return Md5::calculate_chunks(&preprocessed, self.a0, self.b0, self.c0, self.d0);
        }

        /// Returns the md5 hash of the input byte array
        ///
        /// # Limitations
        ///
        /// Works only with complete bytes (multiples of 8 bits)
        ///
        /// # Example
        ///
        /// ```
        /// assert_eq!(
        ///     md5_core::md5_core::Md5::calculate(b"helloworld"),
        ///     0xfc5e038d38a57032085441e7fe7010b0
        /// );
        /// ```
        pub fn calculate(input: &[u8]) -> u128 {
            let preprocessed = Self::preprocess(input, (input.len() * 8).try_into().unwrap());

            return Md5::calculate_chunks(
                &preprocessed,
                0x67452301u32,
                0xEFCDAB89u32,
                0x98BADCFEu32,
                0x10325476u32,
            );
        }

        fn calculate_chunks(buffer: &[u8], a0: u32, b0: u32, c0: u32, d0: u32) -> u128 {
            let mut a0 = Wrapping(a0);
            let mut b0 = Wrapping(b0);
            let mut c0 = Wrapping(c0);
            let mut d0 = Wrapping(d0);

            for n in (0..buffer.len()).step_by(64) {
                let mut a = a0;
                let mut b = b0;
                let mut c = c0;
                let mut d = d0;

                let chunk = &buffer[n..n + 64];
                let m = [
                    Self::as_u32_le(&chunk[..4].try_into().unwrap()),
                    Self::as_u32_le(&chunk[4..8].try_into().unwrap()),
                    Self::as_u32_le(&chunk[8..12].try_into().unwrap()),
                    Self::as_u32_le(&chunk[12..16].try_into().unwrap()),
                    Self::as_u32_le(&chunk[16..20].try_into().unwrap()),
                    Self::as_u32_le(&chunk[20..24].try_into().unwrap()),
                    Self::as_u32_le(&chunk[24..28].try_into().unwrap()),
                    Self::as_u32_le(&chunk[28..32].try_into().unwrap()),
                    Self::as_u32_le(&chunk[32..36].try_into().unwrap()),
                    Self::as_u32_le(&chunk[36..40].try_into().unwrap()),
                    Self::as_u32_le(&chunk[40..44].try_into().unwrap()),
                    Self::as_u32_le(&chunk[44..48].try_into().unwrap()),
                    Self::as_u32_le(&chunk[48..52].try_into().unwrap()),
                    Self::as_u32_le(&chunk[52..56].try_into().unwrap()),
                    Self::as_u32_le(&chunk[56..60].try_into().unwrap()),
                    Self::as_u32_le(&chunk[60..64].try_into().unwrap()),
                ];

                for i in 0..64 {
                    let mut f;
                    let g: u32;

                    if i < 16 {
                        f = (b & c) | (!b & d);
                        g = i;
                    } else if i < 32 {
                        f = (d & b) | (!d & c);
                        g = (5 * i + 1) % 16;
                    } else if i < 48 {
                        f = b ^ c ^ d;
                        g = (3 * i + 5) % 16;
                    } else {
                        f = c ^ (b | !d);
                        g = (7 * i) % 16;
                    }

                    f +=
                        a + Wrapping(m[g as usize]) + Wrapping(Self::PRECOMPUTED_TABLE[i as usize]);
                    a = d;
                    d = c;
                    c = b;
                    b += Wrapping(u32::rotate_left(f.0, Self::SHIFT_TABLE[i as usize]));
                }

                a0 += a;
                b0 += b;
                c0 += c;
                d0 += d;
            }

            return ((a0.0.to_be() as u128) << 96)
                + ((b0.0.to_be() as u128) << 64)
                + ((c0.0.to_be() as u128) << 32)
                + d0.0.to_be() as u128;
        }

        fn preprocess(input: &[u8], original_length_in_bits: u64) -> Vec<u8> {
            let mut preprocessed = input.to_owned();
            let original_length = original_length_in_bits;

            let mut n_bytes_to_push = 56 - (preprocessed.len() % 64);
            if n_bytes_to_push <= 0 {
                n_bytes_to_push = 64 + n_bytes_to_push;
            }

            // append bit '1'. The current implementation only works with complete bytes,
            // so b'10000000 == 0x80
            preprocessed.push(0x80);

            // push enough zeros to have 448 (mod 512) bits
            // n_bytes_to_push - 1 because already pushed 0x80 above
            let mut bytes_to_push = vec![0 as u8; n_bytes_to_push - 1];
            preprocessed.append(&mut bytes_to_push);

            preprocessed.append(&mut Self::u64_to_vector_u8_be(original_length as u64));

            return preprocessed;
        }

        fn u64_to_vector_u8_be(value: u64) -> Vec<u8> {
            let array: [u8; 8] = [
                (value & 0xff).try_into().unwrap(),
                ((value >> 8) & 0xff).try_into().unwrap(),
                ((value >> 16) & 0xff).try_into().unwrap(),
                ((value >> 24) & 0xff).try_into().unwrap(),
                ((value >> 32) & 0xff).try_into().unwrap(),
                ((value >> 40) & 0xff).try_into().unwrap(),
                ((value >> 48) & 0xff).try_into().unwrap(),
                ((value >> 56) & 0xff).try_into().unwrap(),
            ];

            return array.to_vec();
        }

        fn as_u32_le(array: &[u8; 4]) -> u32 {
            ((array[0] as u32) << 0)
                + ((array[1] as u32) << 8)
                + ((array[2] as u32) << 16)
                + ((array[3] as u32) << 24)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::md5_core;

    use md5_core::Md5;

    #[test]
    fn calculate_from_empty_returns_0xd41d8cd98f00b204e9800998ecf8427e() {
        assert_eq!(Md5::calculate(b""), 0xd41d8cd98f00b204e9800998ecf8427e);
    }

    #[test]
    fn calculate_from_helloworld_returns_0xfc5e038d38a57032085441e7fe7010b0() {
        assert_eq!(
            Md5::calculate(b"helloworld"),
            0xfc5e038d38a57032085441e7fe7010b0
        );
    }

    #[test]
    fn calculate_from_448_bits_() {
        assert_eq!(
            Md5::calculate(b"Lorem ipsum dolor sit amet, consectetur adipiscing odio."),
            0x2251013dde7bffaa1780cf66fbbaf4bb
        );
    }

    #[test]
    fn calculate_from_two_chunks() {
        assert_eq!(
            Md5::calculate(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas iaculis efficitur magna ac sagittis. Nullam consectetur nisi non nibh posuere suscipit. Nam velit est, fringilla tincidunt eleifend nec, cursus sit amet metus. Suspendisse id lacus at risus sollicitudin volutpat id in urna. Pellentesque commodo iaculis lectus vitae pulvinar. Morbi ullamcorper ex nisl. Vivamus vel fringilla metus, sit amet malesuada justo. Fusce in lobortis velit. Mauris sed purus mauris. Aenean lobortis bibendum ex quis congue. Etiam sapien nulla, viverra ut lorem blandit."),
            0xba5e84b5ac5785cca9f18469cc8e0193
        );
    }

    #[test]
    fn consume_empty_and_digest() {
        let mut md5 = Md5::new();
        md5 = md5.consume(b"");
        assert_eq!(md5.digest(), 0xd41d8cd98f00b204e9800998ecf8427e);
    }

    #[test]
    fn consume_twice_small_and_digest() {
        let mut md5 = Md5::new();
        md5 = md5.consume(b"hello");
        md5 = md5.consume(b"world");
        assert_eq!(md5.digest(), 0xfc5e038d38a57032085441e7fe7010b0);
    }

    #[test]
    fn consume_twice_two_chunks_and_digest() {
        let mut md5 = Md5::new();
        md5 = md5.consume(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit aliquam.");
        md5 = md5.consume(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit aliquam.");
        assert_eq!(md5.digest(), 0xce13701da5de58af48900b63f2da47ca);
    }
}
