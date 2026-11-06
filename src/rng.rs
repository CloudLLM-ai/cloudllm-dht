//! Injectable randomness: the sans-IO core never touches the OS RNG itself.
//!
//! libtorrent's `aux::random()` and `aux::random_bytes()` become [`Rng`].
//! Production code passes [`SystemRng`]; tests and fuzzers pass [`TestRng`]
//! with a seed so every run is reproducible.

/// A source of random numbers.
///
/// Only [`Rng::fill_bytes`] is required; the rest derive from it.
pub trait Rng {
    /// Fills `dest` with random bytes (libtorrent `aux::random_bytes`).
    fn fill_bytes(&mut self, dest: &mut [u8]);

    /// A random `u32`.
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    /// A random value in `0..=max`, like libtorrent's `aux::random(max)`
    /// (which is inclusive of `max`).
    ///
    /// Uses a multiply-shift reduction; the bias is below `2^-32` per
    /// value, irrelevant for routing and timing jitter.
    fn random(&mut self, max: u32) -> u32 {
        if max == u32::MAX {
            return self.next_u32();
        }
        let wide = u64::from(self.next_u32()) * (u64::from(max) + 1);
        u32::try_from(wide >> 32).expect("(2^32 * (max + 1)) >> 32 fits in u32 for max < u32::MAX")
    }

    /// Twenty random bytes as a hash (libtorrent `aux::random_bytes` into a
    /// `sha1_hash`).
    fn random_hash(&mut self) -> crate::Sha1Hash {
        let mut b = [0u8; crate::sha1_hash::HASH_LEN];
        self.fill_bytes(&mut b);
        crate::Sha1Hash(b)
    }
}

/// The operating system's CSPRNG.
///
/// # Panics
///
/// [`Rng::fill_bytes`] panics if the OS refuses to produce entropy, which
/// only happens on a broken platform; a DHT node cannot choose a safe ID
/// without entropy, so continuing would be worse.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRng;

impl Rng for SystemRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("the OS random number generator must be available");
    }
}

/// A deterministic generator (SplitMix64) for tests and fuzzing.
///
/// Not cryptographically secure; never use it for real node IDs.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::rng::{Rng, TestRng};
/// let mut a = TestRng::new(7);
/// let mut b = TestRng::new(7);
/// assert_eq!(a.next_u32(), b.next_u32());
/// ```
#[derive(Debug, Clone)]
pub struct TestRng(u64);

impl TestRng {
    /// A generator that yields the same sequence for the same `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl Rng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}
