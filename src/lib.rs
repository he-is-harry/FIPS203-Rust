mod converter;
mod sample;
mod ntt;
mod arithmetic;
mod hash_utils;
mod k_pke;
mod ml_kem_internal;

pub mod types;

pub use rand_core::{TryCryptoRng, TryRngCore};
#[cfg(feature = "default-rng")]
use rand_core::{OsRng, OsError};

use crate::{ml_kem_internal::{ml_kem_decaps_internal, ml_kem_encaps_internal, ml_kem_keygen_internal}, types::{CipherText, DecapsKey, EncapsKey, SharedSecretKey}};

const Q: u16 = 3329;

pub enum MlKemParams {
    MlKem512,
    MlKem768,
    MlKem1024
}

pub struct MlKem {
    k: usize,
    eta1: u8,
    eta2: u8,
    du: u8,
    dv: u8
}

impl MlKem {
    pub fn new(params: MlKemParams) -> Self {
        match params {
            MlKemParams::MlKem512 => Self {
                k: 2,
                eta1: 3,
                eta2: 2,
                du: 10,
                dv: 4
            },
            MlKemParams::MlKem768 => Self {
                k: 3,
                eta1: 2,
                eta2: 2,
                du: 10,
                dv: 4
            },
            MlKemParams::MlKem1024 => Self {
                k: 4,
                eta1: 2,
                eta2: 2,
                du: 11,
                dv: 5
            }
        }
    }

    pub fn keygen_with_rng<R: TryCryptoRng + TryRngCore>(&self, rng: &mut R) -> Result<(EncapsKey, DecapsKey), R::Error> {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        rng.try_fill_bytes(&mut d)?;
        rng.try_fill_bytes(&mut z)?;

        Ok(ml_kem_keygen_internal(self.k, self.eta1, &d, &z))
    }

    pub fn encaps_with_rng<R: TryCryptoRng + TryRngCore>(&self, ek: &EncapsKey, rng: &mut R) -> Result<(SharedSecretKey, CipherText), R::Error> {
        let mut m = [0u8; 32];
        rng.try_fill_bytes(&mut m)?;

        Ok(ml_kem_encaps_internal(self.k, self.eta1, self.eta2, self.du, self.dv, ek, &m))
    }

    pub fn decaps(&self, dk: &DecapsKey, c: &CipherText) -> SharedSecretKey {
        ml_kem_decaps_internal(self.k, self.eta1, self.eta2, self.du, self.dv, dk, c)
    }

    #[cfg(feature = "default-rng")]
    pub fn keygen(&self) -> Result<(EncapsKey, DecapsKey), OsError> {
        self.keygen_with_rng(&mut OsRng)
    }

    #[cfg(feature = "default-rng")]
    pub fn encaps(&self, ek: &EncapsKey) -> Result<(SharedSecretKey, CipherText), OsError> {
        self.encaps_with_rng(ek, &mut OsRng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_kem_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(33333);
        let kem = MlKem::new(MlKemParams::MlKem768);

        // If your API returns plain values (no Result):
        let (ek, dk) = kem.keygen_with_rng(&mut rng).expect("random generation for key should not fail");
        let (ssk_enc, ct) = kem.encaps_with_rng(&ek, &mut rng).expect("random generation for the encapsulation should not fail");
        let ssk_dec = kem.decaps(&dk, &ct);

        assert_eq!(ssk_enc.into_bytes(), ssk_dec.into_bytes());
    }

    #[test]
    fn test_kem_roundtrip_using_bytes() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let kem = MlKem::new(MlKemParams::MlKem768);

        // If your API returns plain values (no Result):
        let (ek, dk) = kem.keygen_with_rng(&mut rng).expect("random generation for key should not fail");
        let dk_bytes = dk.into_bytes();
        let create_dk = DecapsKey::from_slice(dk_bytes.as_slice());
        let (ssk_enc, ct) = kem.encaps_with_rng(&ek, &mut rng).expect("random generation for the encapsulation should not fail");
        let ssk_dec = kem.decaps(&create_dk, &ct);

        assert_eq!(ssk_enc.into_bytes(), ssk_dec.into_bytes());
    }
}