/*
 * Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
 * SPDX-License-Identifier: MIT
 *
 * SwarmRoot: factory contract that deploys multisig wallets within one DApp ID.
 * All child wallets inherit the SwarmRoot's DApp ID, enabling gasless
 * internal transactions via gosh.mintshell() from the shared DappConfig.
 *
 * Deploy flow:
 *   1. Owner deploys SwarmRoot via external message → creates DApp ID
 *   2. Owner calls setWalletCode() to store multisig TVC
 *   3. Owner sends SHELL to DappRoot to create DappConfig
 *   4. Owner calls deployWallet() → child multisig inherits DApp ID
 */
pragma gosh-solidity >=0.76.1;
pragma AbiHeader expire;
pragma AbiHeader pubkey;

import "./SwarmMultisigWallet.sol";

interface IDappRoot {
    function deployNewConfigCustom(optional(address) authorityAddress) external;
}

contract SwarmRoot {
    string constant version = "1.0.0";

    // Wallet code storage
    TvmCell _walletCode;
    bool _walletCodeSet;

    // Deployed wallet counter
    uint64 _walletCount;

    // Constants
    uint64 constant DEPLOY_FEE = 2 vmshell;
    uint64 constant MIN_BALANCE = 5 vmshell;

    // Errors
    uint16 constant ERR_NOT_OWNER = 100;
    uint16 constant ERR_NO_WALLET_CODE = 101;

    modifier onlyOwner {
        require(msg.pubkey() == tvm.pubkey(), ERR_NOT_OWNER);
        _;
    }

    constructor() {
        require(msg.pubkey() == tvm.pubkey(), ERR_NOT_OWNER);
        tvm.accept();
        _walletCodeSet = false;
        _walletCount = 0;
    }

    /// Ensure contract has enough balance for operations.
    function ensureBalance() private pure {
        if (address(this).balance > MIN_BALANCE) { return; }
        gosh.mintshell(10 vmshell);
    }

    /// Store the multisig wallet code. Must be called before deployWallet.
    function setWalletCode(TvmCell code) public onlyOwner {
        tvm.accept();
        ensureBalance();
        _walletCode = code;
        _walletCodeSet = true;
    }

    /// Create DappConfig for this swarm's DApp ID.
    /// Calls DappRoot.deployNewConfigCustom with SHELL attached.
    /// dapp_id = SwarmRoot address (from msg.sender).
    function createDappConfig(address dappRoot, uint128 shellAmount) public onlyOwner {
        tvm.accept();
        ensureBalance();
        mapping(uint32 => varuint32) cc;
        cc[2] = varuint32(shellAmount);
        // Call deployNewConfigCustom with SHELL in currencies
        IDappRoot(dappRoot).deployNewConfigCustom{value: 1 vmshell, flag: 1, currencies: cc}(null);
    }

    /// Deploy a new multisig wallet within this swarm's DApp ID.
    /// The wallet inherits DApp ID from SwarmRoot via internal message.
    ///
    /// @param ownerPubkeys Public keys of wallet custodians (uint256[])
    /// @param ownerAddresses Contract addresses of custodians (address[])
    /// @param reqConfirms Required confirmations for transactions
    /// @param initialValue SHELL to convert to VMSHELL in the new wallet
    function deployWallet(
        uint256[] ownerPubkeys,
        address[] ownerAddresses,
        uint8 reqConfirms,
        uint64 initialValue,
        uint256 walletPubkey
    ) public onlyOwner returns (address walletAddress) {
        tvm.accept();
        ensureBalance();
        require(_walletCodeSet, ERR_NO_WALLET_CODE);

        // Build StateInit: salt code with SwarmRoot address + wallet index
        TvmCell saltedCode = _buildWalletCode(_walletCode, _walletCount);
        TvmCell stateInit = _composeWalletStateInit(saltedCode, walletPubkey);

        // Compute deterministic address
        walletAddress = address.makeAddrStd(0, tvm.hash(stateInit));

        // Deploy via internal message → inherits DApp ID
        new SwarmMultisigWallet {
            stateInit: stateInit,
            value: varuint16(DEPLOY_FEE),
            wid: 0,
            flag: 1
        }(ownerPubkeys, ownerAddresses, reqConfirms, reqConfirms, initialValue);

        _walletCount++;
    }

    /// Compute the address of a wallet that would be deployed with given index.
    function getWalletAddress(uint64 walletIndex, uint256 walletPubkey) public view returns (address) {
        require(_walletCodeSet, ERR_NO_WALLET_CODE);
        TvmCell saltedCode = _buildWalletCode(_walletCode, walletIndex);
        TvmCell stateInit = _composeWalletStateInit(saltedCode, walletPubkey);
        return address.makeAddrStd(0, tvm.hash(stateInit));
    }

    /// Get deployment info.
    function getInfo() public view returns (
        string ver,
        uint64 walletCount,
        bool walletCodeSet
    ) {
        return (version, _walletCount, _walletCodeSet);
    }

    // --- Internal ---

    function _buildWalletCode(TvmCell code, uint64 index) private view returns (TvmCell) {
        // Salt with SwarmRoot address + index for unique addresses
        TvmCell salt = abi.encode(version, address(this), index);
        return abi.setCodeSalt(code, salt);
    }

    function _composeWalletStateInit(TvmCell saltedCode, uint256 pubkey) private pure returns (TvmCell) {
        return abi.encodeStateInit({
            code: saltedCode,
            contr: SwarmMultisigWallet,
            pubkey: pubkey,
            varInit: {}
        });
    }
}
