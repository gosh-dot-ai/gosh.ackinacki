<!-- Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd. -->
<!-- SPDX-License-Identifier: MIT -->

# Migration guide

Breaking changes between releases and how to update. Newest first. See also
[CHANGELOG.md](CHANGELOG.md).

---

## 0.4.x → 0.5.0 — `private-note`: RootPN is now caller-supplied

**Who is affected:** only consumers of the optional `private-note` feature that
call `deploy_private_note_from_multisig` / construct `DeployPrivateNoteParams`
(e.g. `gosh-sh/dexdo`). **The lean/default library and every other feature are
unchanged** — nothing to do.

### What changed and why

`gosh-ackinacki` is a *deployment-agnostic* Acki Nacki library. Previous releases
hardcoded a specific DEX deployment inside the `private-note` feature:

- `artifacts::ROOT_PN_ADDRESS` (`0:1010…1010`) — **removed**
- `ROOT_PN_DAPP_ID` (`"0"`, internal const in the voucher forward) — **removed**

Those are *your* deployment's values, not the library's. They are now **required
fields on `DeployPrivateNoteParams`**, so the library no longer bakes in any
particular RootPN.

### API change

`DeployPrivateNoteParams` gains two required fields (both at the top of the struct):

```rust
pub struct DeployPrivateNoteParams {
    pub root_pn_address: Address,   // NEW — the RootPN to mint against
    pub forward_dapp_id: String,    // NEW — DApp id for the generic-Multisig sendTransaction dapp_id
    pub multisig_address: Address,
    pub multisig_keys: KeyPair,
    pub nominal: Nominal,
    pub token_type: TokenType,
    pub halo2_paths: Halo2Paths,
}
```

- `root_pn_address` — the RootPN contract you mint against.
- `forward_dapp_id` — the DApp id passed as the trailing `dapp_id` argument of a
  **generic** ackinacki-kit Multisig's `sendTransaction` (the DApp the RootPN
  destination lives in). It is **ignored** for the 6-arg
  `UpdateCustodianMultisigWallet` forward, which has no such argument — but the
  field is always required (the wallet type is only known at runtime).

`pub const ROOT_PN_ADDRESS` is gone from `gosh_ackinacki::private_note::artifacts`.
If you imported it, define your own constant (see values below).

### How to migrate

**Before (≤ 0.4.0):**

```rust
use gosh_ackinacki::private_note::{deploy_private_note_from_multisig, DeployPrivateNoteParams};

let result = deploy_private_note_from_multisig(&client, DeployPrivateNoteParams {
    multisig_address: wallet_addr,
    multisig_keys:    wallet_keys,
    nominal:          Nominal::N100,
    token_type:       TokenType::Shell,
    halo2_paths,
}).await?;
```

**After (0.5.0):**

```rust
use gosh_ackinacki::private_note::{deploy_private_note_from_multisig, DeployPrivateNoteParams};
use gosh_ackinacki::sdk::Address;

// Your deployment's RootPN — was previously hardcoded in the library.
const ROOT_PN_ADDRESS: &str =
    "0:1010101010101010101010101010101010101010101010101010101010101010";
const ROOT_PN_DAPP_ID: &str = "0";

let result = deploy_private_note_from_multisig(&client, DeployPrivateNoteParams {
    root_pn_address: Address::parse(ROOT_PN_ADDRESS)?,   // NEW
    forward_dapp_id: ROOT_PN_DAPP_ID.to_string(),        // NEW
    multisig_address: wallet_addr,
    multisig_keys:    wallet_keys,
    nominal:          Nominal::N100,
    token_type:       TokenType::Shell,
    halo2_paths,
}).await?;
```

### Values for the current dexdo shellnet deployment

If you were relying on the old hardcoded defaults, these reproduce the previous
behavior **exactly**:

| Field | Value |
|-------|-------|
| `root_pn_address` | `0:1010101010101010101010101010101010101010101010101010101010101010` (the shellnet RootPN premine) |
| `forward_dapp_id` | `"0"` (RootPN is in the system DApp) |

Set them to your network's RootPN + DApp if you deploy elsewhere.

### Not changed

- The embedded `RootPN` / `PrivateNote` **ABIs** stay bundled (they are contract
  *format*, not a deployment address). The wallet-type detection (generic
  Multisig `3a7a5324…` vs `UpdateCustodianMultisigWallet` `8470e1da…`) and the
  fail-fast on an unsupported wallet are unchanged.
- Pin: `gosh-ackinacki = { git = "https://github.com/gosh-dot-ai/gosh.ackinacki", tag = "gosh-ackinacki-v0.5.0", default-features = false, features = ["private-note"] }`.
