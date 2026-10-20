# Vendored multisig wallet artifacts

## UpdateCustodianMultisigWallet_v2  (code_hash 09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded, version 2.2.0)
Source: gosh-sh/ackinacki-kit `contracts/abi/multisig/Multisig.{abi.json,tvc}`
Commit: a98d85fc07ed57926c0a5d7733f0ad9225b13245 (branch dev)
This is the canonical dexdo funding wallet (ackinacki-kit v5.0.0 lineage).
sendTransaction is 7-arg (trailing `dapp_id`); RootPN system DApp id is caller-supplied ("4" on current shellnet).

## UpdateCustodianMultisigWallet_v2 **v2.4.0**  (code_hash cfcaac10d43c8dc062298cb48df097be67cddec52b9cfd558309a7549f01c1f1)
Files: `UpdateCustodianMultisigWallet_v2_4.{abi.json,tvc}`
Source: gosh-sh/acki-nacki `contracts/0.81.0_compiled/updatecustodianmultisigwallet_v2/UpdateCustodianMultisigWallet_v2.{abi.json,tvc}`
Commit: 44fe02ea01e4bb31d431ed57d1f9b3dc3dd88a18
sha256: tvc b0d72acbbdc6af309823e74b96b0b3ffb0f871a5b98316b6e89affdfb56c5c9d
        abi e7573b233667cf50d8edc9ab0ce235f8ac88674ae9610c77d426bec22070f581
This is the CURRENT canonical dexdo funding wallet (dexdo `canonical_multisig::CODE_HASH`);
v2.2.0 (09f596d5) remains supported as dexdo's `LEGACY_SPENDING_CODE_HASH`.
Same 7-arg submitTransaction/sendTransaction shape as v2.2.0, but the CONSTRUCTOR gains
`minBalance` + `targetBalance` (uint128) and the contract adds balance-config / config-update /
code-update entrypoints.
