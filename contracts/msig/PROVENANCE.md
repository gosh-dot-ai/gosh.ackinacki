# Vendored multisig wallet artifacts

## UpdateCustodianMultisigWallet_v2  (code_hash 09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded, version 2.2.0)
Source: gosh-sh/ackinacki-kit `contracts/abi/multisig/Multisig.{abi.json,tvc}`
Commit: a98d85fc07ed57926c0a5d7733f0ad9225b13245 (branch dev)
This is the canonical dexdo funding wallet (ackinacki-kit v5.0.0 lineage).
sendTransaction is 7-arg (trailing `dapp_id`); RootPN system DApp id is caller-supplied ("4" on current shellnet).
