

mod nat_flags;
mod rng;
pub use nat_flags::{flags, predefines};
pub mod simple;


pub fn test() {
    use predefines::*;
    let nat = simple::NAT::<EASY_NAT>::new(&[1], 1000..2000, 0..u16::MAX, 12, 1000*60*2);
}
