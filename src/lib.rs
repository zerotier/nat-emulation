mod nat_flags;
mod rng;
pub use nat_flags::{flags, predefines};
mod nat;
pub use nat::{NATRouter, DestType};
