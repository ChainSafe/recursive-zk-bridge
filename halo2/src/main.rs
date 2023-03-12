#![feature(map_first_last)]
#![feature(slice_flatten)]
#![feature(int_roundings)]
#![feature(generic_const_exprs)]

extern crate core;

mod circuit;
mod aggregation;
mod sha256;
mod hash2curve;

fn main() {
    println!("Hello, ZK!");
}
