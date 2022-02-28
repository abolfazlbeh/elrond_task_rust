extern crate crypto;

use std::fmt;
use std::fmt::Formatter;
use std::ptr::hash;
use rustc_serialize::hex::ToHex;
use ethers::utils::{hex, keccak256};
use ethers::utils::hex::FromHex;

use crate::utils;

const LEAF_SIG: u8 = 0u8;
const INTERNAL_SIG: u8 = 1u8;

type Hash = Vec<u8>;

/// [`MerkelTree`] structure definition
#[derive(Debug)]
pub struct MerkleTree {
    nodes:  Vec<Hash>,
    count_internal_nodes: usize,
    count_leaves: usize,
    sort: bool,
}

/// [`hash_leaf`] function to hash leaves node
fn hash_leaf(value: &str) -> Hash {
    let mut result = vec![0u8; 32];

    let a = Vec::from_hex(value).expect("Invalid hex string");
    // println!(">>>> {:?}", &a);
    result = keccak256(a).to_vec();
    result
}

/// [`hash_internal_nodes`] which get left and right node and make node
/// If right is None --> Then just left node returns
/// If sort parameter is true and right node is not None --> then the pair is sorted first and then will be hashed
fn hash_internal_nodes(left: &Hash, right: Option<&Hash>, sort: bool) -> Hash {
    let mut result = vec![0u8; 32];

    let mut temp = vec![0u8; left.len() * 2];
    if let Some(r) = right {
        let mut p: Vec<Hash> = Vec::new();
        p.push((&left).to_vec());
        p.push((&r).to_vec());

        if sort {
            p.sort();
        }
        temp = [&p[0][..], &p[1][..]].concat();
        result = keccak256(temp).to_vec();
    } else {
        result = left.clone();
    }
    // println!("{:?}", result.to_hex());
    result
}

/// [`build_upper_level`] loop through hashed nodes and make the upper level nodes
fn build_upper_level(nodes: &[Hash], sort: bool) -> Vec<Hash> {
    let mut row = Vec::with_capacity((nodes.len() + 1) / 2);
    let mut i = 0;

    while i < nodes.len() {
        if i + 1 < nodes.len() {
            row.push(hash_internal_nodes(&nodes[i], Some(&nodes[i + 1]), sort));
            i += 2;
        } else {
            row.push(hash_internal_nodes(&nodes[i], None, sort));
            i += 1;
        }
    }

    if row.len() > 1 && row.len() % 2 != 0 {
        let last_node = row.last().unwrap().clone();
        row.push(last_node);
    }

    row
}

/// [`build_internal_nodes`] loop through initial nodes and make the tree till just root left
fn build_internal_nodes(nodes: &mut Vec<Vec<u8>>, count_internal_nodes: usize, sort: bool) {
    let mut parents = build_upper_level(&nodes[count_internal_nodes..], sort);

    let mut upper_level_start = count_internal_nodes - parents.len();
    let mut upper_level_end = upper_level_start + parents.len();
    nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);

    while parents.len() > 1{
        parents = build_upper_level(parents.as_slice(), sort);

        upper_level_start -= parents.len();
        upper_level_end = upper_level_start + parents.len();
        nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);
    }

    nodes[0] = parents.remove(0);
}

/// [`calculate_internal_nodes_count`] just calculate the space needed for all tree nodes plus all internal nodes
fn calculate_internal_nodes_count(count_leaves: usize) -> usize {
    utils::next_power_of_2(count_leaves) - 1
}

/// [`_build_from_leaves`] the internal function that hash leaves and make the new `MerkleTree`
fn _build_from_leaves(leaves: &[Hash], sort: bool) -> MerkleTree {
    let count_leaves = leaves.len();
    let count_internal_nodes = calculate_internal_nodes_count(count_leaves);
    let mut nodes = vec![Vec::new(); count_internal_nodes + count_leaves];

    nodes[count_internal_nodes..].clone_from_slice(leaves);

    build_internal_nodes(&mut nodes, count_internal_nodes, sort);

    MerkleTree {
        sort: sort,
        nodes: nodes,
        count_internal_nodes: count_internal_nodes,
        count_leaves: count_leaves,
    }
}

/// [`MerkleTree`] implementation
impl MerkleTree  {
    /// [`MerkleTree::build`] to build `MerkleTree` from nodes
    pub fn build(values: &[&str], sort: bool) -> MerkleTree {
        MerkleTree::build_with_hasher(values, sort)
    }

    pub fn build_with_hasher(values: &[&str], sort: bool) -> MerkleTree {
        let count_leaves = values.len();
        assert!(count_leaves > 1, "expected more than 1 value, received {}", count_leaves);
        let mut leaves: Vec<Hash> = values.iter().map(|v| hash_leaf(v)).collect();

        if sort {
            leaves.sort();
        }
        _build_from_leaves(leaves.as_slice(), sort)
    }

    /// [`MerkleTree::root_hash`] to return root hash as array
    pub fn root_hash(&self) -> &Hash {
        &self.nodes[0]
    }

    /// [`MerkleTree::root_hash_str`] to return root hash as hex string
    pub fn root_hash_str(&self) -> String {
        use rustc_serialize::hex::ToHex;
        self.nodes[0].as_slice().to_hex()
    }

    /// [`MerkleTree::leaves`] to return just leaves
    pub fn leaves(&self) -> &[Hash] {
        &self.nodes[self.count_internal_nodes..]
    }

    /// [`MerkleTree::proof`] get `leaf` and `index` and returns the inclusion-proof of `MerkleTree`
    pub fn proof(&mut self,leaf: &str, mut index: isize) -> Vec<&Hash> {
        if index == -1 {
            if  self.nodes[self.count_internal_nodes..].contains(&hash_leaf(leaf)) {
                index = self.nodes.iter().position(|r| r == &hash_leaf(leaf)).unwrap() as isize;
            }
        }
        if index <= -1 {
            return Vec::new();
        }

        let mut proof: Vec<&Hash> = Vec::new();
        while index != 0 {
            let is_right_node = index % 2;
            let pair_index = if is_right_node == 0  {index - 1} else { index +1};

            if pair_index >= 0 &&( pair_index as usize) < self.nodes.len() {
                proof.push(&self.nodes[pair_index as usize])
            }

            index = ((index - 1) / 2) | 0;
        }

        proof
    }
}

/// Just simple test for `MerkleTree`
#[cfg(test)]
mod tests {
    use crypto::digest::Digest;
    use crypto::sha3::{Sha3, Sha3Mode};
    use crate::FromHex;
    use super::AsBytes;
    use super::Hash;
    use super::MerkleTree;

    #[test]
    fn test_root_hash() {
        let address2 = "f17f52151EbEF6C7334FAD080c5704D77216b732";
        let address3 = "C5fdf4076b8F3A5357c5E395ab970B5B54098Fef";
        let address1 = "821aEa9a577a9b44299B9c15c88cf3087F3b5544";


        let mut t: MerkleTree = MerkleTree::build(&[address2, address3, address1], true);
        assert_eq!("4bc499384a270746f40e2bb610517d2e9edb8cc61605c3754f194472f772e821",
                   t.root_hash_str());

        // assert_eq!("fe1e31239bf810e6ac7dd7c54a9ed47fa8be6c0997d7e81266e3fa2d5d9d988f",
        //            t.root_hash_str());
    }

}