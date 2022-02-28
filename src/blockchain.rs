use std::env;
use std::str::FromStr;
use web3::api::Eth;
use web3::contract::{Contract, Options};
use web3::transports::WebSocket;
use web3::types::{Address, Bytes, U256};
use web3::{Error, signing, Web3};
use crate::MerkleTree;
use crate::config;
use crate::mt::AsBytes;


/// [`ContractIwf`] Structure - to handle contract interaction
#[derive!(Debug)]
pub struct ContractIwf {
    web3_instance: web3::Web3<WebSocket>, // web3 instance
    owner_address: Vec<u8>,
    mt: MerkleTree, // merkletree instance
    contract: Contract<WebSocket>, // contract instance
    whitelist_addresses: Vec<[u8]>,
    root_hash: Vec<u8>,
}

/// [`ContractIwf`] implementation to implement needed functions to have interaction with Smart Contract
impl ContractIwf {
    /// [`ContractIwf::new`] creates a new `ContractIwf` instance
    pub async fn new(network_address: &str, owner_address: &str) -> Result<ContractIwf, Error> {
        let websocket = web3::transports::WebSocket::new(network_address).await?;
        let instance = web3::Web3::new(websocket);

        // Initialize the contract
        let contract_address = Address::from_str(CONTRACT_ADDRESS).unwrap();
        let contract = Contract::from_json(instance.eth(), contract_address, include_bytes!(CONTRACT_ABI_JSON)).unwrap();

        Ok(ContractIwf {
            web3_instance: instance,
            owner_address: owner_address.to_vec(),
            mt: MerkleTree::build(&[], true),
            contract: contract,
            whitelist_addresses: Vec::new(),
            root_hash: "".to_vec(),
        })
    }

    /// [`ContractIwf::add_address`] - add address to internal `MerkleTree` and get the root hash
    /// and update SmartContract root hash
    pub fn add_address(&mut self, mut address: &str, secret_key: &str) -> String {
        if address.starts_with("0x") {
            address = &address[2..];
        }

        self.whitelist_addresses.as_mut().push(*address.as_byte_slice());
        // build merkletree
        self.mt = MerkleTree::build(self.whitelist_addresses.iter().map(|s| s as &str).collect(), true);
        self.root_hash = self.mt.root_hash_str().to_vec();

        let c = Bytes::from(&self.root_hash);

        let seckey: secp256k1::key::SecretKey = secret_key.parse().unwrap();
        let tx_hash = self.contract.signed_call("updateMTRoot", (c, ), Options::default(), seckey).await?;
        tx_hash.to_string()
    }

    /// [`ContractIwf::get_state`] to get last state from smart contract
    pub fn get_state(&mut self, from_address: &str,) -> u128 {
        let addr = Address::from_str(from_address).unwrap();
        let result: U256 = self.contract.query("getState", (), addr, Options::default(), None).await?;
        result.as_u128()
    }

    /// [`ContractIwf::set_state`] to set state into smart contract
    /// Because just the whitelisted addresses have this role --> The proof array is provided to smart contract
    /// to check whether it has the right access
    pub fn set_state(&mut self, mut address: &str, secret_key: &str, value: u128) -> String {
        if address.starts_with("0x") {
            address = &address[2..];
        }
        let val = U256::from(value);

        // get proofs
        let proofs =  self.mt.proof(address, -1).iter().map(|v| Bytes::from(v)).collect();

        let seckey: secp256k1::key::SecretKey = secret_key.parse().unwrap();
        let tx_hash = self.contract.signed_call("updateMTRoot", (val, proofs), Options::default(), seckey).await?;
        tx_hash.to_string()
    }
}

/// Just simple test for `ContractIwf`
#[cfg(test)]
mod tests {
    use std::ops::Add;
    use std::thread;
    use std::time::Duration;
    use crate::blockchain::ContractIwf;

    #[test]
    fn test_set_state() {
        let address2 = "0xf17f52151EbEF6C7334FAD080c5704D77216b732";
        let address3 = "0xC5fdf4076b8F3A5357c5E395ab970B5B54098Fef";
        let address1 = "0x821aEa9a577a9b44299B9c15c88cf3087F3b5544";

        let mut cont = ContractIwf::new(NETWORK_ADDRESS, OWNER_ADDRESS).await?;
        cont.add_address(address1, OWNER_PRIVATE_KEY);
        cont.add_address(address2, OWNER_PRIVATE_KEY);
        cont.add_address(address3, OWNER_PRIVATE_KEY);

        thread::sleep(Duration::from_millis(5000));

        let pre_state = cont.get_state(OWNER_ADDRESS);
        let hash_tx = cont.set_state(address1, OWNER_PRIVATE_KEY, pre_state.add(5u128));

        thread::sleep(Duration::from_millis(5000));
        let new_state = cont.get_state(OWNER_ADDRESS);

        assert_eq!(new_state - pre_state, 5u128, "The state does not match");
    }

    #[test]
    fn test_set_state_event(){}
}