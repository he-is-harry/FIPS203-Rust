use crate::Q;

#[inline(always)]
pub(crate) fn mod_q_mul(a: u16, b: u16) -> u16 {
    ((a as u32 * b as u32) % Q as u32) as u16
}

#[inline(always)]
pub(crate) fn mod_q_sub(a: u16, b: u16) -> u16 {
    if a >= b {
        a - b
    } else {
        a + Q - b
    }
}

#[inline(always)]
pub(crate) fn mod_q_add(a: u16, b: u16) -> u16 {
    let sum = a + b;
    if sum >= Q {
        sum - Q
    } else {
        sum
    }
}
