use crate::{converter::{byte_decode, byte_encode, byte_encode_mult, compress, decompress}, hash_utils::{g_33, prf},
ntt::{ntt, ntt_inv, poly_add, poly_mat_mult, poly_mat_transpose_mult, poly_sub, poly_vec_add, poly_vec_mult}, sample::{sample_ntt, sample_poly_cbd}};

pub(crate) fn pke_key_gen(k: usize, eta1: u8, d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (rho, sigma) = g_33(d, k.try_into().unwrap());
    let mut n = 0;
    let mut a_mtx = vec![vec![[0u16; 256]; k]; k];
    for i in 0..k {
        for j in 0..k {
            a_mtx[i][j] = sample_ntt(&rho, j as u8, i as u8);
        }
    }
    let mut s = vec![[0u16; 256]; k];
    for i in 0..k {
        s[i] = sample_poly_cbd(&prf(eta1, &sigma, n));
        n += 1;
    }
    let mut e = vec![[0u16; 256]; k];
    for i in 0..k {
        e[i] = sample_poly_cbd(&prf(eta1, &sigma, n));
        n += 1;
    }
    let s_ntt: Vec<[u16; 256]> = s.iter().map(|poly| ntt(poly)).collect();
    let e_ntt: Vec<[u16; 256]> = e.iter().map(|poly| ntt(poly)).collect();
    let t = poly_vec_add(&poly_mat_mult(&a_mtx, &s_ntt), &e_ntt); 
    let mut ek_pke = byte_encode_mult(k, &t, 12);
    ek_pke.extend(rho);
    let dk_pke = byte_encode_mult(k, &s_ntt, 12);
    (ek_pke, dk_pke)
}

pub(crate) fn pke_encrypt(k: usize, eta1: u8, eta2: u8, du: u8, dv: u8, ek: &[u8], m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    let mut n = 0;
    let mut t = Vec::with_capacity(k);
    for i in 0..k {
        t.push(byte_decode(&ek[384 * i ..384 * (i + 1)], 12));
    }
    let rho: [u8; 32] = ek[384 * k .. 384 * k + 32].try_into().unwrap();
    let mut a_mtx = vec![vec![[0u16; 256]; k]; k];
    for i in 0..k {
        for j in 0..k {
            a_mtx[i][j] = sample_ntt(&rho, j as u8, i as u8);
        }
    }
    let mut y = vec![[0u16; 256]; k];
    for i in 0..k {
        y[i] = sample_poly_cbd(&prf(eta1, &r, n));
        n += 1;
    }
    let mut e1 = vec![[0u16; 256]; k];
    for i in 0..k {
        e1[i] = sample_poly_cbd(&prf(eta2, &r, n));
        n += 1;
    }
    let e2 = sample_poly_cbd(&prf(eta2, r, n));
    let y_ntt: Vec<[u16; 256]> = y.iter().map(|poly| ntt(poly)).collect();
    // Compute u = NTT_inv(A^T \cdot y_ntt) + e_1
    let mut u = poly_mat_transpose_mult(&a_mtx, &y_ntt);
    for (u_i, e1_i) in u.iter_mut().zip(e1.iter()) {
        *u_i = ntt_inv(u_i);
        poly_add(u_i, e1_i);
    }
    let mu = decompress(1, &byte_decode(m, 1));
    // Compute v = NTT_inv(t \cdot y_ntt) + e_2 + mu
    let mut v = ntt_inv(&poly_vec_mult(&t, &y_ntt));
    poly_add(&mut v, &e2);
    poly_add(&mut v, &mu);
    // Compute c1 = ByteEncode(Compress(u))
    let mut comp_u = Vec::with_capacity(k);
    for i in 0..k {
        comp_u.push(compress(du, &u[i]));
    }
    let mut c = byte_encode_mult(k, &comp_u, du);
    // Compute c2 = ByteEncode(Compress(v))
    c.append(&mut byte_encode(&compress(dv, &v), dv));
    
    c
}

pub(crate) fn pke_decrypt(k: usize, du: u8, dv: u8, dk: &[u8], c: &[u8]) -> Vec<u8> {
    debug_assert!(c.len() == 32 * ((du as usize) * k + dv as usize), "Input byte array must be of length 32 * d");

    let mut u = Vec::with_capacity(k);
    for i in 0..k {
        u.push(decompress(du, &byte_decode(&c[32 * (du as usize) * i .. 32 * (du as usize) * (i + 1)], du)));
    }

    let v = decompress(dv, &byte_decode(&c[32 * (du as usize) * k .. 32 * ((du as usize) * k + (dv as usize))], dv));

    let mut s = Vec::with_capacity(k);
    for i in 0..k {
        s.push(byte_decode(&dk[32 * 12 * i .. 32 * 12 * (i + 1)], 12));
    }

    // Compute w = v' - NTT^-1(s \cdot NTT(u'))
    let u_ntt: Vec<[u16; 256]> = u.iter().map(|poly| ntt(poly)).collect();
    let w = poly_sub(&v, &ntt_inv(&poly_vec_mult(&s, &u_ntt)));

    let m = byte_encode(&compress(1, &w), 1);

    m
}
