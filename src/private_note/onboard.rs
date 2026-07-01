// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! In-process replacement for the historical `onboard_user_shellnet` binary.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::private_note::artifacts::{PRIVATE_NOTE_ABI_JSON, ROOT_PN_ABI_JSON};
use crate::private_note::halo2::multisig_voucher::mint_voucher_via_multisig;
use crate::private_note::halo2::paths::Halo2Paths;
use crate::private_note::proof::{
    hex_u256_to_dec, pubkey_to_dec, CURRENCY_ID_SHELL, ECC_SHELL_DEPOSIT_RAW,
};
use crate::private_note::{Nominal, TokenType};
use crate::sdk::{Address, ChainClient, KeyPair};

pub struct DeployPrivateNoteParams {
    /// The RootPN contract to mint against. This library is deployment-agnostic:
    /// the caller supplies the RootPN address for its network (e.g. the dexdo
    /// shellnet premine `0:1010…1010`) rather than the library hardcoding one.
    pub root_pn_address: Address,
    /// The DApp id used as the trailing `dapp_id` argument of a *generic*
    /// Multisig's `sendTransaction` (the DApp the RootPN destination lives in;
    /// `"0"` for dexdo's system-DApp RootPN). Ignored for the 6-arg
    /// UpdateCustodianMultisigWallet forward, which has no such argument.
    pub forward_dapp_id: String,
    pub multisig_address: Address,
    pub multisig_keys: KeyPair,
    pub nominal: Nominal,
    pub token_type: TokenType,
    pub halo2_paths: Halo2Paths,
}

/// CLI-compatible result shape. It intentionally mirrors the fields dexdo
/// previously adapted from `onboard_user_shellnet`'s `pn_state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPrivateNoteResult {
    pub endpoint: String,
    pub nominal: String,
    pub token_type: u32,
    pub raw_value: u64,
    pub ecc_shell_deposit: u64,
    pub pn_address: String,
    pub deposit_identifier_hash: String,
    pub owner_public_key_hex: String,
    pub owner_secret_key_hex: String,
    pub deployed_at_unix: u64,
    pub shell_funded: bool,
    pub sanity_checked: bool,
}

pub async fn deploy_private_note_from_multisig(
    client: &ChainClient,
    params: DeployPrivateNoteParams,
) -> Result<DeployPrivateNoteResult> {
    let root_pn = params.root_pn_address.clone();
    let raw_value = params.nominal.raw_value(params.token_type);

    // STEP 1: deposit voucher + deployPrivateNote.
    let pn_keys = KeyPair::generate();
    let deposit_zk = mint_voucher_via_multisig(
        client.endpoint(),
        &root_pn,
        &params.forward_dapp_id,
        &params.multisig_address,
        &params.multisig_keys,
        pn_keys.public_hex(),
        params.token_type.id(),
        raw_value,
        false,
        &params.halo2_paths,
    )
    .await
    .map_err(|e| anyhow!("halo2 deposit voucher: {e}"))?;

    let dih_dec = hex_u256_to_dec(&deposit_zk.deposit_identifier_hash_hex)?;
    client
        .call(
            &root_pn,
            ROOT_PN_ABI_JSON,
            "deployPrivateNote",
            json!({
                "zkproof": deposit_zk.proof,
                "depositIdentifierHash": dih_dec,
                "finalLayerHistoricalHashRoot": hex_u256_to_dec(&deposit_zk.final_layer_historical_hash_root_hex)?,
                "voucherNominalFr": hex_u256_to_dec(&deposit_zk.voucher_nominal_fr_hex)?,
                "tokenTypeFr": hex_u256_to_dec(&deposit_zk.token_type_fr_hex)?,
                "ephemeralPubkey": pubkey_to_dec(pn_keys.public_hex())?,
                "value": deposit_zk.voucher_value,
                "tokenType": deposit_zk.voucher_token_type,
                "layerNumber": deposit_zk.layer_number,
            }),
            &pn_keys,
        )
        .await
        .map_err(|e| anyhow!("RootPN.deployPrivateNote: {e}"))?;

    let pn_address = private_note_address(client, &root_pn, &dih_dec).await?;
    let pn = Address::parse(&pn_address)?;
    wait_active(client, &pn, Duration::from_secs(120)).await?;
    let deployed_at_unix = now_unix()?;

    // STEP 2: SHELL gas voucher + sendEccShellToPrivateNote.
    let gas_zk = mint_voucher_via_multisig(
        client.endpoint(),
        &root_pn,
        &params.forward_dapp_id,
        &params.multisig_address,
        &params.multisig_keys,
        pn_keys.public_hex(),
        CURRENCY_ID_SHELL,
        ECC_SHELL_DEPOSIT_RAW,
        true,
        &params.halo2_paths,
    )
    .await
    .map_err(|e| anyhow!("halo2 SHELL gas voucher: {e}"))?;

    client
        .call(
            &root_pn,
            ROOT_PN_ABI_JSON,
            "sendEccShellToPrivateNote",
            json!({
                "proof": gas_zk.proof,
                "nullifierHash": hex_u256_to_dec(&gas_zk.deposit_identifier_hash_hex)?,
                "depositIdentifierHash": dih_dec,
                "finalLayerHistoricalHashRoot": hex_u256_to_dec(&gas_zk.final_layer_historical_hash_root_hex)?,
                "voucherNominalFr": hex_u256_to_dec(&gas_zk.voucher_nominal_fr_hex)?,
                "tokenTypeFr": hex_u256_to_dec(&gas_zk.token_type_fr_hex)?,
                "value": gas_zk.voucher_value,
                "layerNumber": gas_zk.layer_number,
                "recipientEphemeralPubkey": pubkey_to_dec(pn_keys.public_hex())?,
            }),
            &pn_keys,
        )
        .await
        .map_err(|e| anyhow!("RootPN.sendEccShellToPrivateNote: {e}"))?;
    tokio::time::sleep(Duration::from_secs(5)).await;

    // STEP 3: sanity check via PrivateNote.getDetails.
    client
        .run_getter(&pn, PRIVATE_NOTE_ABI_JSON, "getDetails", json!({}))
        .await?
        .ok_or_else(|| anyhow!("PrivateNote.getDetails returned no output"))?;

    Ok(DeployPrivateNoteResult {
        endpoint: client.endpoint().to_string(),
        nominal: params.nominal.label().to_string(),
        token_type: params.token_type.id(),
        raw_value,
        ecc_shell_deposit: ECC_SHELL_DEPOSIT_RAW,
        pn_address,
        deposit_identifier_hash: dih_dec,
        owner_public_key_hex: pn_keys.public_hex().to_string(),
        owner_secret_key_hex: pn_keys.secret_hex().to_string(),
        deployed_at_unix,
        shell_funded: true,
        sanity_checked: true,
    })
}

async fn private_note_address(
    client: &ChainClient,
    root_pn: &Address,
    deposit_identifier_hash: &str,
) -> Result<String> {
    let out = client
        .run_getter(
            root_pn,
            ROOT_PN_ABI_JSON,
            "getPrivateNoteAddress",
            json!({ "depositIdentifierHash": deposit_identifier_hash }),
        )
        .await?
        .ok_or_else(|| anyhow!("RootPN.getPrivateNoteAddress returned no output"))?;
    out.get("privateNoteAddress")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("RootPN.getPrivateNoteAddress missing privateNoteAddress: {out}"))
}

async fn wait_active(client: &ChainClient, address: &Address, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(acc) = client.get_account(address).await? {
            if acc.is_active() {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "{address} did not become Active within {}s",
                timeout.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn now_unix() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("system clock before epoch: {e}"))?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_result_serializes_to_old_state_field_names() {
        let state = DeployPrivateNoteResult {
            endpoint: "https://shellnet.ackinacki.org".to_string(),
            nominal: "N100".to_string(),
            token_type: 1,
            raw_value: 100_000_000_000,
            ecc_shell_deposit: 100_000_000_000,
            pn_address: "0:abc".to_string(),
            deposit_identifier_hash: "123".to_string(),
            owner_public_key_hex: "pub".to_string(),
            owner_secret_key_hex: "sec".to_string(),
            deployed_at_unix: 42,
            shell_funded: true,
            sanity_checked: true,
        };
        let v = serde_json::to_value(state).unwrap();
        assert_eq!(v["pn_address"], "0:abc");
        assert_eq!(v["deposit_identifier_hash"], "123");
        assert_eq!(v["shell_funded"], true);
        assert_eq!(v["sanity_checked"], true);
    }
}
