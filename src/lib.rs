mod nat_flags;
mod rng;
pub use nat_flags::{flags, predefines};
pub mod nat;

pub fn test() {
    use predefines::*;
    let nat = nat::NAT::<EASY_NAT, 1>::new([1], 1000..2000, 0..u16::MAX, 12, 1000 * 60 * 2);
}
