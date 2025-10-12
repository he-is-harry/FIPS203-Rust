use sha3::{Digest, Sha3_256, Sha3_512, Shake256, digest::{Update, ExtendableOutput, XofReader}};

pub(crate) fn g(seed: &[u8], extra: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, seed);
    Digest::update(&mut hasher, extra);
    let result = hasher.finalize();

    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&result[..32]);
    b.copy_from_slice(&result[32..]);

    (a, b)
}

pub(crate) fn g_33(seed: &[u8], k: u8) -> ([u8; 32], [u8; 32]) {
    g(seed, &[k])
}

pub(crate) fn h(s: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, &s);
    hasher.finalize().into()
}

pub(crate) fn j(s: &[u8], c: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();

    hasher.update(s);
    hasher.update(c);

    let mut xof = hasher.finalize_xof();

    let mut output = [0u8; 32];
    xof.read(&mut output);

    output
}

pub(crate) fn prf(eta: u8, s: &[u8; 32], b: u8) -> Vec<u8> {
    debug_assert!(eta == 2 || eta == 3, "eta must be 2 or 3");

    let mut hasher = Shake256::default();
    hasher.update(s);
    hasher.update(&[b]); // 1-byte input

    let mut xof = hasher.finalize_xof();

    let mut output = vec![0u8; 64 * eta as usize];
    xof.read(&mut output);

    output
}
