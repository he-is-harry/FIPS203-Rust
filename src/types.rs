use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecretKey(pub(crate) [u8; 32]);

impl SharedSecretKey {
    pub fn into_bytes(self) -> [u8; 32] { self.0 }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncapsKey(pub(crate) Vec<u8>);

impl EncapsKey {
    pub fn into_bytes(self) -> Vec<u8> { self.0.clone() }
    pub fn from_slice(bytes: &[u8]) -> Self {
        EncapsKey(bytes.to_vec())
    }
}

impl From<Vec<u8>> for EncapsKey {
    fn from(bytes: Vec<u8>) -> Self {
        EncapsKey(bytes)
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DecapsKey(pub(crate) Vec<u8>);

impl DecapsKey {
    pub fn into_bytes(self) -> Vec<u8> { self.0.clone() }
    pub fn from_slice(bytes: &[u8]) -> Self {
        DecapsKey(bytes.to_vec())
    }
}

impl From<Vec<u8>> for DecapsKey {
    fn from(bytes: Vec<u8>) -> Self {
        DecapsKey(bytes)
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CipherText(pub(crate) Vec<u8>);

impl CipherText {
    pub fn into_bytes(self) -> Vec<u8> { self.0.clone() }
    pub fn from_slice(bytes: &[u8]) -> Self {
        CipherText(bytes.to_vec())
    }
}

impl From<Vec<u8>> for CipherText {
    fn from(bytes: Vec<u8>) -> Self {
        CipherText(bytes)
    }
}