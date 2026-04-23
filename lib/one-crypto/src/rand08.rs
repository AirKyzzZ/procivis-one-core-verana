use rand::{CryptoRng, RngExt};
use rand_old::Error;

/// Some of the crates in our stack still depend on rand 0.8 and have no new
/// stable versions compatible with rand 0.10. This wrapper allows for passing
/// a rand 0.10 RNG to crates expecting a rand 0.8 equivalent.
pub struct CompatWrapper<'a>(pub &'a mut dyn CryptoRng);

impl<'a> rand_old::CryptoRng for CompatWrapper<'a> {}
impl<'a> rand_old::RngCore for CompatWrapper<'a> {
    fn next_u32(&mut self) -> u32 {
        self.0.sample(rand::distr::StandardUniform)
    }

    fn next_u64(&mut self) -> u64 {
        self.0.sample(rand::distr::StandardUniform)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
