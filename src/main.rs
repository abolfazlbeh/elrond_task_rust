extern crate core;

use ethers::abi::ParamType::String;
use ethers::utils::{hex, keccak256};
use rustc_serialize::hex::ToHex;
use crate::hex::FromHex;
use crate::mt::MerkleTree;

mod mt;
mod utils;
mod blockchain;
mod config;

fn main() {
}
