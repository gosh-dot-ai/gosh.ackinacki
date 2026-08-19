// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Registry of supported multisig wallet versions + a public deploy entry point.
//!
//! One table is the single source of truth for **every** multisig the crate
//! understands, used by two consumers:
//!   * [`deploy_multisig`] — deploy a fresh wallet of an explicitly chosen
//!     version (issue gosh-dot-ai/gosh.ackinacki#5);
//!   * the private-note funding-forward path
//!     (`private_note::halo2::multisig_voucher`), which must accept a caller's
//!     funding wallet by its on-chain `code_hash`.
//!
//! Adding a future wallet version is one [`MultisigKind`] variant plus its
//! vendored artifacts — both consumers pick it up automatically.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use crate::sdk::{Address, ChainClient, KeyPair};
use crate::wallet::giver::GiverClient;

/// Generic ackinacki-kit v2.1.0 user/dashboard Multisig. **Forward-only** — no
/// TVC is vendored, so it can fund a note but cannot be deployed by this crate.
/// Its `sendTransaction` carries a trailing `dapp_id` (7-arg).
pub const GENERIC_CODE_HASH: &str =
    "3a7a53248ff39fde936a4274eab143b5fac94feac0d8e2e2748aac5e74538d5f";

/// Historical gosh.ackinacki operational `UpdateCustodianMultisigWallet` (v1).
/// 6-arg `sendTransaction` (no `dapp_id`). Deployable.
pub const UPDATE_CUSTODIAN_V1_CODE_HASH: &str =
    "8470e1da28a2b4c742b5f7edefdd97db81c79e726f8a8b0be78d921adaf32414";

/// `UpdateCustodianMultisigWallet_v2` **v2.2.0**, from `gosh-sh/ackinacki-kit`
/// v5.0.0. 7-arg `sendTransaction` / `submitTransaction` (trailing `dapp_id`).
/// Deployable. Still accepted as a funding wallet — dexdo calls this its
/// `LEGACY_SPENDING_CODE_HASH` — but new deploys should use
/// [`UPDATE_CUSTODIAN_V2_4_CODE_HASH`]. See `contracts/msig/PROVENANCE.md`.
pub const UPDATE_CUSTODIAN_V2_CODE_HASH: &str =
    "09f596d5bb4f63d7f2b18020ee0b7c9e88114dc90010389cc594c67954655ded";

/// `UpdateCustodianMultisigWallet_v2` **v2.4.0** — the CURRENT canonical funding
/// wallet, from `gosh-sh/acki-nacki` `contracts/0.81.0_compiled/…`. Same 7-arg
/// call shape as v2.2.0, but its **constructor takes two extra arguments**
/// (`minBalance`, `targetBalance`) and it adds balance/config/code-update
/// entrypoints. Deployable. See `contracts/msig/PROVENANCE.md`.
pub const UPDATE_CUSTODIAN_V2_4_CODE_HASH: &str =
    "cfcaac10d43c8dc062298cb48df097be67cddec52b9cfd558309a7549f01c1f1";

/// Minimal generic-Multisig ABI (7-arg `sendTransaction`, with `dapp_id`). Kept
/// inline because this crate never deploys the generic wallet — it only forwards
/// through a caller-owned one — so only the send shape is needed.
const GENERIC_ABI_JSON: &str = r#"{
  "ABI version": 2,
  "version": "2.4",
  "header": ["pubkey", "time", "expire"],
  "functions": [
    {
      "name": "sendTransaction",
      "inputs": [
        { "name": "dest", "type": "address" },
        { "name": "value", "type": "uint128" },
        { "name": "cc", "type": "map(uint32,varuint32)" },
        { "name": "bounce", "type": "bool" },
        { "name": "flags", "type": "uint8" },
        { "name": "payload", "type": "cell" },
        { "name": "dapp_id", "type": "uint256" }
      ],
      "outputs": [{ "name": "value0", "type": "address" }]
    }
  ],
  "events": [],
  "data": []
}"#;

const V1_ABI_JSON: &str = include_str!("../../contracts/UpdateCustodianMultisigWallet.abi.json");
const V1_TVC: &[u8] = include_bytes!("../../contracts/UpdateCustodianMultisigWallet.tvc");
const V2_ABI_JSON: &str =
    include_str!("../../contracts/msig/UpdateCustodianMultisigWallet_v2.abi.json");
const V2_TVC: &[u8] = include_bytes!("../../contracts/msig/UpdateCustodianMultisigWallet_v2.tvc");
const V2_4_ABI_JSON: &str =
    include_str!("../../contracts/msig/UpdateCustodianMultisigWallet_v2_4.abi.json");
const V2_4_TVC: &[u8] =
    include_bytes!("../../contracts/msig/UpdateCustodianMultisigWallet_v2_4.tvc");

/// A supported multisig wallet version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultisigKind {
    /// Generic ackinacki-kit Multisig — forward-only (fund a note; not deployable).
    Generic,
    /// `UpdateCustodianMultisigWallet` v1.
    UpdateCustodianV1,
    /// `UpdateCustodianMultisigWallet_v2` **v2.2.0** — the previous canonical
    /// funding wallet. Still accepted for funding; prefer [`Self::UpdateCustodianV2_4`]
    /// for new deploys.
    UpdateCustodianV2,
    /// `UpdateCustodianMultisigWallet_v2` **v2.4.0** — the CURRENT canonical
    /// funding wallet (`minBalance`/`targetBalance` constructor).
    UpdateCustodianV2_4,
}

impl MultisigKind {
    /// Resolve a wallet by its on-chain `code_hash` (bare or `0x`-prefixed).
    pub fn from_code_hash(code_hash: &str) -> Result<Self> {
        let h = code_hash
            .trim()
            .trim_start_matches("0x")
            .to_ascii_lowercase();
        match h.as_str() {
            GENERIC_CODE_HASH => Ok(Self::Generic),
            UPDATE_CUSTODIAN_V1_CODE_HASH => Ok(Self::UpdateCustodianV1),
            UPDATE_CUSTODIAN_V2_CODE_HASH => Ok(Self::UpdateCustodianV2),
            UPDATE_CUSTODIAN_V2_4_CODE_HASH => Ok(Self::UpdateCustodianV2_4),
            other => Err(anyhow!(
                "unsupported multisig code_hash {other}; supported: generic Multisig \
                 {GENERIC_CODE_HASH}, UpdateCustodianMultisigWallet v1 \
                 {UPDATE_CUSTODIAN_V1_CODE_HASH}, v2.2.0 {UPDATE_CUSTODIAN_V2_CODE_HASH}, \
                 v2.4.0 {UPDATE_CUSTODIAN_V2_4_CODE_HASH}"
            )),
        }
    }

    /// The wallet's on-chain code hash (bare 64-hex).
    pub fn code_hash(self) -> &'static str {
        match self {
            Self::Generic => GENERIC_CODE_HASH,
            Self::UpdateCustodianV1 => UPDATE_CUSTODIAN_V1_CODE_HASH,
            Self::UpdateCustodianV2 => UPDATE_CUSTODIAN_V2_CODE_HASH,
            Self::UpdateCustodianV2_4 => UPDATE_CUSTODIAN_V2_4_CODE_HASH,
        }
    }

    /// The wallet's ABI JSON.
    pub fn abi_json(self) -> &'static str {
        match self {
            Self::Generic => GENERIC_ABI_JSON,
            Self::UpdateCustodianV1 => V1_ABI_JSON,
            Self::UpdateCustodianV2 => V2_ABI_JSON,
            Self::UpdateCustodianV2_4 => V2_4_ABI_JSON,
        }
    }

    /// The deploy TVC, or `None` for a forward-only wallet (no vendored code).
    pub fn tvc(self) -> Option<&'static [u8]> {
        match self {
            Self::Generic => None,
            Self::UpdateCustodianV1 => Some(V1_TVC),
            Self::UpdateCustodianV2 => Some(V2_TVC),
            Self::UpdateCustodianV2_4 => Some(V2_4_TVC),
        }
    }

    /// The wallet's constructor arguments. **v2.4.0 takes two extra fields**
    /// (`minBalance`, `targetBalance`) that the older builds do not accept, so the
    /// shape is per-version rather than one hardcoded object. `"0"`/`"0"` matches
    /// the canonical operational wallet dexdo deploys (auto-topup disabled).
    fn constructor_args(self, owners: &[String], req_confirms: u8) -> Value {
        let mut ctor = json!({
            "owners_pubkey": owners,
            "owners_address": [],
            "reqConfirms": req_confirms,
            "reqConfirmsData": req_confirms,
            "value": "0",
        });
        if self == Self::UpdateCustodianV2_4 {
            ctor["minBalance"] = Value::String("0".to_string());
            ctor["targetBalance"] = Value::String("0".to_string());
        }
        ctor
    }

    /// Whether this crate can deploy the wallet (a TVC is vendored).
    pub fn is_deployable(self) -> bool {
        self.tvc().is_some()
    }

    /// Whether `sendTransaction` carries a trailing `dapp_id` argument (7-arg).
    /// v1 is 6-arg; the generic Multisig and both v2 builds are 7-arg.
    pub fn has_dapp_id_arg(self) -> bool {
        matches!(
            self,
            Self::Generic | Self::UpdateCustodianV2 | Self::UpdateCustodianV2_4
        )
    }

    /// The wallet call that forwards `RootPN.generateVoucher` for a note-funding
    /// voucher: `(method_name, params)`. The method and shape differ per version:
    ///
    /// - **v1** — `sendTransaction`, 6-arg, no `dapp_id`.
    /// - **generic** — `sendTransaction`, 7-arg with a trailing `dapp_id`.
    /// - **v2** — `submitTransaction` with a trailing `dapp_id` (note the field is
    ///   `flag`, singular). This is the immediate 1-of-1 path the canonical dexdo
    ///   funding wallet uses; `dapp_id` routes the internal `generateVoucher` to
    ///   the DApp the RootPN lives in (e.g. `"4"` on shellnet 4.0.33).
    ///
    /// `bounce = true` and `flag(s) = 1` throughout.
    pub fn forward_call(
        self,
        dest: &str,
        dapp_id: &str,
        cc: Map<String, Value>,
        native_value: u128,
        payload: String,
    ) -> (&'static str, Value) {
        let cc = Value::Object(cc);
        let value = native_value.to_string();
        match self {
            Self::UpdateCustodianV2 | Self::UpdateCustodianV2_4 => (
                "submitTransaction",
                json!({
                    "dest": dest, "value": value, "cc": cc, "bounce": true,
                    "flag": 1, "payload": payload, "dapp_id": dapp_id,
                }),
            ),
            Self::Generic => (
                "sendTransaction",
                json!({
                    "dest": dest, "value": value, "cc": cc, "bounce": true,
                    "flags": 1, "payload": payload, "dapp_id": dapp_id,
                }),
            ),
            Self::UpdateCustodianV1 => (
                "sendTransaction",
                json!({
                    "dest": dest, "value": value, "cc": cc, "bounce": true,
                    "flags": 1, "payload": payload,
                }),
            ),
        }
    }
}

/// Where a freshly deployed wallet's initial balance comes from. The distinction
/// is deliberate: the giver exists only on testnet, so a mainnet deploy must be
/// `Prefunded` and this crate never silently half-deploys an unfunded wallet.
pub enum FundingSource<'a> {
    /// Testnet: fund the deterministic deploy address from the giver with
    /// `native_amount` vmshell before sending the deploy message.
    Giver {
        giver: &'a GiverClient,
        native_amount: u128,
    },
    /// The deterministic deploy address is ALREADY funded by the caller (the
    /// mainnet path). The deploy is sent and awaited; if the address was not in
    /// fact funded the account never activates and [`deploy_multisig`] fails
    /// cleanly rather than reporting a half-deployed wallet.
    Prefunded,
}

/// Parameters for [`deploy_multisig`].
pub struct DeployMultisigParams<'a> {
    /// Which wallet version to deploy — always explicit, no default.
    pub kind: MultisigKind,
    /// The keypair that signs the deploy. Unless `owner_pubkeys` is non-empty,
    /// this key is the sole custodian (the 1-of-1 operational-wallet case).
    pub deployer: &'a KeyPair,
    /// Custodian public keys (bare or `0x`-prefixed 64-hex). Empty ⇒ `[deployer]`.
    pub owner_pubkeys: &'a [String],
    /// Confirmations required per transaction. `1` gives an immediate
    /// `sendTransaction` (the funding-wallet shape the private-note flow needs).
    pub req_confirms: u8,
    /// Where the wallet's initial balance comes from.
    pub funding: FundingSource<'a>,
    /// How long to wait for the wallet to become `Active` after the deploy.
    pub activate_timeout_secs: u64,
}

/// Deploy a multisig wallet of an explicitly chosen [`MultisigKind`] and return
/// its address once it is `Active` on-chain.
///
/// The result satisfies the constraints the private-note funding flow imposes:
/// the deployed `code_hash` is verified to equal the requested version, and the
/// wallet is constructed with `owner_pubkeys` (default `[deployer]`) and the
/// given `req_confirms`, so the deployer's key is a custodian.
///
/// Fails closed: a forward-only kind (no TVC) is rejected up front, and an
/// unfunded `Prefunded` deploy surfaces as an activation-timeout error, never a
/// half-deployed wallet.
pub async fn deploy_multisig(
    client: &ChainClient,
    params: DeployMultisigParams<'_>,
) -> Result<Address> {
    let tvc = params.kind.tvc().ok_or_else(|| {
        anyhow!(
            "{:?} is forward-only (no TVC vendored) and cannot be deployed by this crate",
            params.kind
        )
    })?;

    let owners: Vec<String> = if params.owner_pubkeys.is_empty() {
        vec![format!("0x{}", params.deployer.public_hex())]
    } else {
        params
            .owner_pubkeys
            .iter()
            .map(|p| {
                let bare = p.trim().trim_start_matches("0x");
                format!("0x{bare}")
            })
            .collect()
    };

    let ctor = params.kind.constructor_args(&owners, params.req_confirms);

    let msg = crate::airegistry::deploy::build_deploy(
        client.context(),
        params.kind.abi_json(),
        tvc,
        json!({}),
        ctor,
        params.deployer.public_hex(),
        params.deployer.secret_hex(),
    )
    .await
    .map_err(|e| anyhow!("build {:?} deploy message: {e}", params.kind))?;

    // Fund the deterministic deploy address (testnet giver) BEFORE sending the
    // StateInit; the mainnet path assumes the caller already funded it.
    if let FundingSource::Giver {
        giver,
        native_amount,
    } = &params.funding
    {
        giver
            .fund_deploy_address(&msg.address, *native_amount)
            .await
            .map_err(|e| anyhow!("giver-fund deploy address {}: {e}", msg.address))?;
    }

    let address = client
        .deploy(&msg, params.activate_timeout_secs)
        .await
        .map_err(|e| match params.funding {
            FundingSource::Prefunded => anyhow!(
                "{:?} deploy did not activate — if using FundingSource::Prefunded, the \
                 deterministic address {} must be funded before deploy: {e}",
                params.kind,
                msg.address
            ),
            FundingSource::Giver { .. } => {
                anyhow!("{:?} deploy did not activate: {e}", params.kind)
            }
        })?;

    // Belt-and-suspenders: confirm the on-chain code hash is the requested
    // version (guaranteed by the vendored TVC, re-checked to catch any drift).
    if let Some(acc) = client.get_account(&address).await? {
        if let Some(got) = acc.code_hash.as_deref() {
            let want = params.kind.code_hash();
            if got.trim_start_matches("0x").to_ascii_lowercase() != want {
                return Err(anyhow!(
                    "deployed wallet {address} code_hash {got} != requested {:?} {want}",
                    params.kind
                ));
            }
        }
    }

    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tvm_block::Deserializable;

    fn tvc_code_hash(tvc: &[u8]) -> String {
        let cell = tvm_types::read_single_root_boc(tvc).unwrap();
        let si = tvm_block::StateInit::construct_from_cell(cell).unwrap();
        format!("{:x}", si.code().unwrap().repr_hash())
    }

    #[test]
    fn vendored_tvc_code_hashes_match_the_registry() {
        assert_eq!(
            tvc_code_hash(V1_TVC),
            UPDATE_CUSTODIAN_V1_CODE_HASH,
            "v1 TVC code hash drifted"
        );
        assert_eq!(
            tvc_code_hash(V2_TVC),
            UPDATE_CUSTODIAN_V2_CODE_HASH,
            "v2.2.0 TVC code hash drifted"
        );
        assert_eq!(
            tvc_code_hash(V2_4_TVC),
            UPDATE_CUSTODIAN_V2_4_CODE_HASH,
            "v2.4.0 TVC code hash drifted"
        );
    }

    #[test]
    fn constructor_shape_is_per_version() {
        let owners = vec!["0xabc".to_string()];
        // v2.4.0 REQUIRES the two balance fields; older builds must not get them
        // (their constructor has no such parameters and encoding would fail).
        let v24 = MultisigKind::UpdateCustodianV2_4.constructor_args(&owners, 1);
        assert_eq!(v24["minBalance"], "0");
        assert_eq!(v24["targetBalance"], "0");
        assert_eq!(v24["reqConfirms"], 1);
        for older in [
            MultisigKind::UpdateCustodianV2,
            MultisigKind::UpdateCustodianV1,
        ] {
            let c = older.constructor_args(&owners, 1);
            assert!(c.get("minBalance").is_none(), "{older:?} has no minBalance");
            assert!(c.get("targetBalance").is_none());
        }
    }

    #[test]
    fn constructor_args_match_each_vendored_abi() {
        // The built constructor object must carry exactly the parameters the
        // wallet's own ABI declares — this is what catches a future version whose
        // constructor changed again.
        let owners = vec!["0xabc".to_string()];
        for kind in [
            MultisigKind::UpdateCustodianV1,
            MultisigKind::UpdateCustodianV2,
            MultisigKind::UpdateCustodianV2_4,
        ] {
            let abi: Value = serde_json::from_str(kind.abi_json()).unwrap();
            let declared: Vec<String> = abi["functions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["name"] == "constructor")
                .expect("constructor in ABI")["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["name"].as_str().unwrap().to_string())
                .collect();
            let built: Vec<String> = kind
                .constructor_args(&owners, 1)
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect();
            let mut d = declared.clone();
            let mut b = built.clone();
            d.sort();
            b.sort();
            assert_eq!(d, b, "{kind:?}: ctor args {built:?} != ABI {declared:?}");
        }
    }

    #[test]
    fn from_code_hash_roundtrips_and_normalizes_prefix() {
        for kind in [
            MultisigKind::Generic,
            MultisigKind::UpdateCustodianV1,
            MultisigKind::UpdateCustodianV2,
        ] {
            assert_eq!(
                MultisigKind::from_code_hash(kind.code_hash()).unwrap(),
                kind
            );
            // 0x-prefixed + upper-case must resolve identically.
            let pref = format!("0x{}", kind.code_hash().to_ascii_uppercase());
            assert_eq!(MultisigKind::from_code_hash(&pref).unwrap(), kind);
        }
        assert!(MultisigKind::from_code_hash("deadbeef").is_err());
    }

    #[test]
    fn deployability_and_send_shape_per_version() {
        // Only v2 and generic carry the trailing dapp_id; v1 is 6-arg.
        assert!(MultisigKind::UpdateCustodianV2.has_dapp_id_arg());
        assert!(MultisigKind::Generic.has_dapp_id_arg());
        assert!(!MultisigKind::UpdateCustodianV1.has_dapp_id_arg());

        // Generic is forward-only; the custodian wallets are deployable.
        assert!(!MultisigKind::Generic.is_deployable());
        assert!(MultisigKind::UpdateCustodianV1.is_deployable());
        assert!(MultisigKind::UpdateCustodianV2.is_deployable());
        assert!(MultisigKind::UpdateCustodianV2_4.is_deployable());
        assert!(MultisigKind::UpdateCustodianV2_4.has_dapp_id_arg());

        // v1: sendTransaction, 6-arg, no dapp_id.
        let cc = Map::new();
        let (m1, v1) = MultisigKind::UpdateCustodianV1.forward_call(
            "0:aa",
            "4",
            cc.clone(),
            2_000_000_000,
            "payload".into(),
        );
        assert_eq!(m1, "sendTransaction");
        assert!(v1.get("dapp_id").is_none());
        assert_eq!(v1["flags"], 1);

        // generic: sendTransaction, 7-arg with dapp_id.
        let (mg, vg) =
            MultisigKind::Generic.forward_call("0:aa", "4", cc.clone(), 2_000_000_000, "p".into());
        assert_eq!(mg, "sendTransaction");
        assert_eq!(vg["dapp_id"], "4");

        // v2: submitTransaction, 7-arg with dapp_id, `flag` singular (dexdo path).
        let (m2, v2) = MultisigKind::UpdateCustodianV2.forward_call(
            "0:aa",
            "4",
            cc,
            2_000_000_000,
            "p".into(),
        );
        assert_eq!(m2, "submitTransaction");
        assert_eq!(v2["dapp_id"], "4");
        assert_eq!(v2["flag"], 1);
        assert_eq!(v2["bounce"], true);
    }
}
