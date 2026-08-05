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
        .map_err(|e| explain_submit_abort("deployPrivateNote", e, &dih_dec, None))?;

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
        .map_err(|e| {
            explain_submit_abort("sendEccShellToPrivateNote", e, &dih_dec, Some(&pn_address))
        })?;
    tokio::time::sleep(Duration::from_secs(5)).await;

    // STEP 3: REQUIRE the on-chain effect before reporting success. A
    // `sendEccShellToPrivateNote` that returns Ok only means the call was
    // accepted — it does not prove the note is funded. Poll the PN's ECC[2]
    // SHELL balance (from the trailing settled read) until it reflects the gas
    // deposit; a note that never receives its gas is unusable, so fail closed
    // with a clear error. The gas voucher is already paid, so the error directs
    // the caller to verify/recover manually — never to blindly re-run.
    match observe_shell_effect(
        client,
        &pn,
        u128::from(ECC_SHELL_DEPOSIT_RAW),
        Duration::from_secs(90),
    )
    .await
    {
        GasEffect::Funded => {}
        // A terminal successful read showed the gas genuinely short — confirmed
        // failure. The gas voucher was already paid, so do not advise a blind
        // re-run (that mints another gas voucher = another spend).
        GasEffect::ConfirmedShort(shell) => {
            return Err(anyhow!(
                "PrivateNote {pn_address} is Active but a settled read shows its ECC[2] SHELL \
                 balance is {shell} < {ECC_SHELL_DEPOSIT_RAW} — the gas voucher was already minted \
                 and paid, but the note is not funded. Do NOT blindly re-run (a re-run mints \
                 another gas voucher = another wallet spend). Verify PrivateNote {pn_address} \
                 on-chain and recover manually; automatic recovery is tracked in issue #4 (open)."
            ));
        }
        // The trailing observation was a read failure (or none ever succeeded) —
        // an observer/chain-read outage, NOT evidence the gas is missing (it may
        // have landed during the outage). Report UNKNOWN, not a confirmed failure.
        GasEffect::Unobserved => {
            return Err(anyhow!(
                "could not settle PrivateNote {pn_address} ECC[2] SHELL balance within the window \
                 (chain-read outage on the final observation) — the deploy outcome is UNKNOWN, \
                 not a confirmed missing effect. Verify the note on-chain before deciding whether \
                 to re-run; the gas voucher may already have funded it."
            ));
        }
    }

    // Best-effort sanity getter. Newer `sold` emits a return-message action the
    // pinned tvm-sdk `run_tvm` cannot parse ("can not parse actions"), so a
    // getter failure must NOT fail an otherwise-complete, effect-verified deploy.
    let sanity_checked = client
        .run_getter(&pn, PRIVATE_NOTE_ABI_JSON, "getDetails", json!({}))
        .await
        .ok()
        .flatten()
        .is_some();

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
        sanity_checked,
    })
}

/// Parse the EXACT numeric `exit_code=<n>` token from a surfaced BM error string
/// (see `wallet::query::check_bm_error`). Matches the whole integer, so
/// `exit_code=4030` is `4030`, never `403` — a substring test would misclassify
/// an adjacent code as a contract error and hand out the wrong guidance.
fn parsed_exit_code(s: &str) -> Option<i64> {
    let tail = s.split("exit_code=").nth(1)?.trim_start();
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<i64>().ok()
}

/// Turn a RootPN submit failure into an actionable error, classifying the EXACT
/// abort code. The voucher for this leg has already been minted and paid before
/// the submit can abort, so the guidance must NOT be a blind "re-run" (that mints
/// another voucher = another wallet spend). Instead it names the paid operation
/// and tells the operator to verify/recover manually.
///
/// - **403 `ERR_INVALID_HISTORY_PROOF`**: the layer-0 history root aged out while
///   proving. Not auto-retried (at `W=128` the next layer is ~16384 blocks away);
///   automatic same-voucher recovery is issue #4 (open).
/// - **137 `ERR_INVALID_ZKPROOF`**: the proof does not verify — a circuit/kit
///   mismatch (what the bad `e7944e9` pin produced), NOT stale history and NOT
///   retryable. Fail closed pointing at the kit pin.
/// - **any other code**: passed through unchanged on its real value.
fn explain_submit_abort(
    method: &str,
    e: anyhow::Error,
    dih_dec: &str,
    pn_address: Option<&str>,
) -> anyhow::Error {
    let paid = match pn_address {
        Some(pn) => format!(
            "A voucher for this leg was already minted and paid \
             (depositIdentifierHash={dih_dec}, privateNoteAddress={pn})."
        ),
        None => format!(
            "A voucher for this leg was already minted and paid \
             (depositIdentifierHash={dih_dec}; the PrivateNote address is derivable via \
             RootPN.getPrivateNoteAddress)."
        ),
    };
    match parsed_exit_code(&e.to_string()) {
        Some(403) => anyhow!(
            "RootPN.{method} aborted 403 ERR_INVALID_HISTORY_PROOF ({e}). The layer-0 history \
             proof aged out of RootPN's window while proving. {paid} Do NOT blindly re-run — a \
             re-run mints a NEW voucher (and on the gas leg starts a fresh deposit/note flow), \
             i.e. another wallet spend. Verify the on-chain state of the address above and \
             recover manually; automatic same-voucher recovery is tracked in issue #4 (open)."
        ),
        Some(137) => anyhow!(
            "RootPN.{method} aborted 137 ERR_INVALID_ZKPROOF ({e}). The zk proof does not verify \
             against the on-chain circuit — a field/circuit/halo2-kit mismatch, NOT a stale \
             history root; re-running will not help. Verify the dexdo-halo2-kit pin matches the \
             deployed gosh.zkhalo2verify. {paid} Failing closed; do not re-run blindly."
        ),
        _ => anyhow!("RootPN.{method}: {e}"),
    }
}

/// Outcome of watching a PrivateNote's ECC[2] SHELL balance after the gas leg.
/// The three cases are kept distinct so a **read outage** is never reported as a
/// **confirmed** missing effect (a false failure after money was spent).
#[derive(Debug, PartialEq, Eq)]
enum GasEffect {
    /// A read succeeded and showed the gas at or above the deposit.
    Funded,
    /// A read succeeded but the balance stayed below the deposit.
    ConfirmedShort(u128),
    /// No read ever succeeded in the window — an observer/chain-read outage,
    /// NOT evidence the gas is missing.
    Unobserved,
}

/// Reduce ONE `get_account` outcome to the trailing observation state used at the
/// deadline. Only a **successful** read may confirm a shortfall, so a read error
/// (outage) collapses to `None` (UNKNOWN) regardless of any earlier success — a
/// gas transfer could have landed during a trailing outage. A successful read is
/// its balance (account absent = a real `0`).
fn read_to_terminal(read: std::result::Result<Option<u128>, ()>) -> Option<u128> {
    match read {
        Ok(Some(shell)) => Some(shell),
        Ok(None) => Some(0),
        Err(()) => None,
    }
}

/// Classify the TERMINAL observation at the deadline: a below-min balance from a
/// settled successful read is a confirmed shortfall; a trailing outage (or no
/// successful read at all) is UNKNOWN, never a confirmed missing effect.
fn classify_gas_effect(terminal: Option<u128>) -> GasEffect {
    match terminal {
        Some(shell) => GasEffect::ConfirmedShort(shell),
        None => GasEffect::Unobserved,
    }
}

/// Poll a PrivateNote's ECC[2] SHELL balance until it reaches `min_shell` or the
/// window elapses. `Funded` returns as soon as any read settles at/above the
/// deposit; otherwise the classification uses the TRAILING read so a read outage
/// on the last observation is reported UNKNOWN, not a confirmed shortfall.
async fn observe_shell_effect(
    client: &ChainClient,
    pn: &Address,
    min_shell: u128,
    timeout: Duration,
) -> GasEffect {
    let deadline = Instant::now() + timeout;
    loop {
        // `Result<Option<u128>, ()>` is `Copy`, so `read` is usable twice below.
        let read = client
            .get_account(pn)
            .await
            .map(|o| o.map(|a| a.shell()))
            .map_err(|_| ());
        if let Ok(Some(shell)) = read {
            if shell >= min_shell {
                return GasEffect::Funded;
            }
        }
        if Instant::now() >= deadline {
            // Classify from the TRAILING read only.
            return classify_gas_effect(read_to_terminal(read));
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
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

    fn abort(method: &str, msg: &str) -> anyhow::Error {
        explain_submit_abort(method, anyhow!("{msg}"), "0xDIH", Some("0:pn"))
    }

    #[test]
    fn exit_code_is_parsed_as_an_exact_integer() {
        assert_eq!(
            parsed_exit_code("[TVM_ERROR]: exit_code=403 compute phase"),
            Some(403)
        );
        assert_eq!(parsed_exit_code("...exit_code=137; error={...}"), Some(137));
        // Adjacent codes must NOT be read as 403/137.
        assert_eq!(parsed_exit_code("...exit_code=4030..."), Some(4030));
        assert_eq!(parsed_exit_code("...exit_code=1370..."), Some(1370));
        assert_eq!(parsed_exit_code("no code here"), None);
    }

    #[test]
    fn abort_codes_are_classified_distinctly() {
        // 403 ERR_INVALID_HISTORY_PROOF = aged-out history root. The voucher is
        // already paid, so the guidance must NOT be a blind re-run.
        let s403 = abort("deployPrivateNote", "exit_code=403 compute phase").to_string();
        assert!(s403.contains("ERR_INVALID_HISTORY_PROOF"), "{s403}");
        assert!(s403.contains("already minted and paid"), "{s403}");
        assert!(s403.contains("Do NOT blindly re-run"), "{s403}");

        // 137 ERR_INVALID_ZKPROOF = the proof does not verify (circuit/kit
        // mismatch), NOT stale history and NOT retryable.
        let s137 = abort("deployPrivateNote", "exit_code=137 compute phase").to_string();
        assert!(s137.contains("ERR_INVALID_ZKPROOF"), "{s137}");
        assert!(s137.contains("will not help"), "{s137}");
        assert!(!s137.contains("ERR_INVALID_HISTORY_PROOF"), "{s137}");

        // Adjacent codes must NOT be misclassified as the contract errors.
        let s4030 = abort("deployPrivateNote", "exit_code=4030 compute phase").to_string();
        assert!(!s4030.contains("ERR_INVALID"), "4030 is not 403: {s4030}");
        let s1370 = abort("deployPrivateNote", "exit_code=1370 compute phase").to_string();
        assert!(!s1370.contains("ERR_INVALID"), "1370 is not 137: {s1370}");

        // Any other error passes through unchanged.
        let other = abort("deployPrivateNote", "QUEUE_OVERFLOW");
        assert!(other.to_string().contains("QUEUE_OVERFLOW"));
        assert!(!other.to_string().contains("ERR_INVALID"));
    }

    #[test]
    fn gas_effect_terminal_observation_governs() {
        // A settled successful read below the deposit = CONFIRMED short; never
        // having a successful read = OUTAGE (unknown), not "gas missing".
        assert_eq!(classify_gas_effect(None), GasEffect::Unobserved);
        assert_eq!(classify_gas_effect(Some(0)), GasEffect::ConfirmedShort(0));
        assert_eq!(classify_gas_effect(Some(42)), GasEffect::ConfirmedShort(42));

        // The TRAILING read governs: a read error collapses to None (UNKNOWN),
        // regardless of an earlier successful low read.
        assert_eq!(read_to_terminal(Err(())), None);
        assert_eq!(read_to_terminal(Ok(Some(7))), Some(7));
        assert_eq!(read_to_terminal(Ok(None)), Some(0)); // absent account = real 0

        // Sequence "short then outage" → terminal outage → UNKNOWN (the transfer
        // may have landed during the outage), NOT a confirmed shortfall.
        let short_then_outage = [Ok(Some(0u128)), Err(()), Err(())]
            .into_iter()
            .fold(None, |_, r| read_to_terminal(r));
        assert_eq!(
            classify_gas_effect(short_then_outage),
            GasEffect::Unobserved
        );

        // Sequence "outage then final short read" → terminal is the settled short
        // read → CONFIRMED short.
        let outage_then_short = [Err(()), Err(()), Ok(Some(5u128))]
            .into_iter()
            .fold(None, |_, r| read_to_terminal(r));
        assert_eq!(
            classify_gas_effect(outage_then_short),
            GasEffect::ConfirmedShort(5)
        );
    }
}
