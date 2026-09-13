// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Embedded contract ABI and TVC for the multisig wallet.

use std::sync::LazyLock;

use tvm_abi::Contract;

pub static MULTISIG_ABI_JSON: &str =
    include_str!("../../contracts/UpdateCustodianMultisigWallet.abi.json");

pub static MULTISIG_TVC: &[u8] =
    include_bytes!("../../contracts/UpdateCustodianMultisigWallet.tvc");

pub static MULTISIG_ABI: LazyLock<Contract> = LazyLock::new(|| {
    Contract::load(MULTISIG_ABI_JSON.as_bytes()).expect("embedded multisig ABI must be valid")
});

pub static GIVER_ABI_JSON: &str = include_str!("../../contracts/giver/GiverV3.abi.json");

pub static GIVER_ABI: LazyLock<Contract> = LazyLock::new(|| {
    Contract::load(GIVER_ABI_JSON.as_bytes()).expect("embedded giver ABI must be valid")
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_loads() {
        let _ = &*MULTISIG_ABI;
    }

    #[test]
    fn abi_has_expected_functions() {
        let abi = &*MULTISIG_ABI;
        assert!(abi.function("constructor").is_ok());
        assert!(abi.function("sendTransaction").is_ok());
        assert!(abi.function("submitTransaction").is_ok());
        assert!(abi.function("confirmTransaction").is_ok());
        assert!(abi.function("getCustodians").is_ok());
        assert!(abi.function("getTransactions").is_ok());
    }

    #[test]
    fn tvc_is_nonempty() {
        assert!(MULTISIG_TVC.len() > 100);
    }
}
