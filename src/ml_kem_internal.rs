use crate::{hash_utils::{g, h, j}, k_pke::{pke_decrypt, pke_encrypt, pke_key_gen}};
use subtle::{ConditionallySelectable, ConstantTimeEq};

pub(crate) fn ml_kem_keygen_internal(k: usize, eta1: u8, d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (ek_pke, dk_pke) = pke_key_gen(k, eta1, d);

    // 384k + 384k + 32 + 32
    let mut dk = Vec::with_capacity(768 * k + 64);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek_pke);
    dk.extend_from_slice(&h(&ek_pke));
    dk.extend_from_slice(z);

    (ek_pke, dk)
}

pub(crate) fn ml_kem_encaps_internal(k: usize, eta1: u8, eta2: u8, du: u8, dv: u8, ek: &[u8], m: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let (k_cap, r) = g(m, &h(ek));

    let c = pke_encrypt(k, eta1, eta2, du, dv, ek, m, &r);

    (k_cap, c)
}

pub(crate) fn ml_kem_decaps_internal(k: usize, eta1: u8, eta2: u8, du: u8, dv: u8, dk: &[u8], c: &[u8]) -> [u8; 32] {
    let dk_pke = &dk[0 .. 384 * k];
    let ek_pke = &dk[384 * k .. 768 * k + 32];
    let h = &dk[768 * k + 32 .. 768 * k + 64];
    let z = &dk[768 * k + 64 .. 768 * k + 96];

    let m = pke_decrypt(k, du, dv, dk_pke, c);

    let (mut k_prime, r_prime) = g(&m, h);
    
    let k_bar = j(z, c);

    let c_prime = pke_encrypt(k, eta1, eta2, du, dv, ek_pke, m.as_slice().try_into().unwrap(), &r_prime);

    k_prime.conditional_assign(&k_bar, c.ct_ne(&c_prime));
    k_prime
}