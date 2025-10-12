# FIPS 203: ML-KEM Implementation in Rust

A Rust implementation of **FIPS 203 (ML-KEM)** — the standardized module-lattice-based Key Encapsulation Mechanism derived from **Kyber**, part of the NIST Post-Quantum Cryptography standardization effort.

The post-quantum cryptographic library to be used in Harry's Password Manager.

> ⚠️ **Caution: Use at Your Own Risk**
>
> This library was developed for educational purposes. While it has been implemented to the best of my knowledge and tested for functional correctness,  **it has not been vetted, audited, or endorsed by any cryptographic or security agencies.** I am not a professional cryptographer or security engineer. 

---

## ✨ Overview

This crate provides:
- Parameter sets for **ML-KEM-512**, **ML-KEM-768**, and **ML-KEM-1024**
- Full key generation, encapsulation, and decapsulation operations
- Custom RNG and default RNG's (using `OsRng`) are supported

---

## ⚙️ Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/he-is-harry/FIPS203-Rust.git
```

### 2. Add as Dependency
In your `Cargo.toml` file add the package as a dependency with the path to the cloned repository.
```
[dependencies]
fips203-rust = { path = "/path/to/FIPS203-Rust" }
```
Optionally, if you wish to provide your own RNGs, you can also set default features to false.
```
[dependencies]
fips203-rust = { path = "/path/to/FIPS203-Rust", default-features=false }
```

## 🚀 Example Usage
```rust
// Import the library and desired parameter set
use fips203_rust::{MlKem, MlKemParams::MlKem768};

// Default using OsRng
let kem = MlKem::new(MlKem768);

let (ek, dk) = kem.keygen().unwrap();
let (ssk_enc, ct) = kem.encaps(&ek).unwrap();
let ssk_dec = kem.decaps(&dk, &ct);

assert_eq!(ssk_enc, ssk_dec);

// Custom RNG
let mut rng = ChaCha20Rng::from_os_rng();
let kem = MlKem::new(MlKem768);

let (ek, dk) = kem.keygen().unwrap();
let (ssk_enc, ct) = kem.encaps_with_rng(&ek, &mut rng).unwrap();
let ssk_dec = kem.decaps(&dk, &ct);

assert_eq!(ssk_enc, ssk_dec);
```

