//! E2E test: AI Service Marketplace
//!
//! Two swarms pay each other for services on shellnet.
//! All events tracked in gosh.memory.
//!
//! Swarm Alpha ("Data Providers"):
//!   Wallet Alpha = the root multisig (already deployed)
//!   agent_alpha, controller_alpha, owner (shared)
//!
//! Swarm Beta ("Analysts"):
//!   Wallet Beta = deployed from root via internal message (inherits DApp ID)
//!   agent_beta, controller_beta, owner (shared)
//!
//! Scenario:
//!   1. Deploy Wallet Beta from Wallet Alpha (same DApp ID → gasless internal)
//!   2. Fund Wallet Beta with VMSHELL from Alpha
//!   3. Beta pays Alpha 50 SHELL for "research data"
//!   4. Alpha pays Beta 20 SHELL for "data quality review"
//!   5. Verify all events in gosh.memory

use gosh_ackinacki::wallet::contracts::MULTISIG_ABI;
use gosh_ackinacki::wallet::deploy::{prepare_deploy, DeployParams};
use gosh_ackinacki::wallet::query::send_message;
use tvm_abi::token::Tokenizer;
use tvm_block::Serializable;

const ENDPOINT: &str = "https://shellnet.ackinacki.org";

// Wallet Alpha (root, already deployed)
const ALPHA_ADDR: &str = "0:03079cdd1f5c3044fb3f7993becb2f581ffc1e3d128db4afc411e7870af883c3";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let agent_alpha = std::env::var("AGENT_ALPHA_SECRET").expect("set AGENT_ALPHA_SECRET env var");
    let ctrl_alpha = std::env::var("CTRL_ALPHA_SECRET").expect("set CTRL_ALPHA_SECRET env var");
    let owner = std::env::var("OWNER_SECRET").expect("set OWNER_SECRET env var");
    let agent_beta = std::env::var("AGENT_BETA_SECRET").expect("set AGENT_BETA_SECRET env var");
    let ctrl_beta = std::env::var("CTRL_BETA_SECRET").expect("set CTRL_BETA_SECRET env var");
    let http = reqwest::Client::new();
    println!("=== AI Service Marketplace E2E Test ===\n");

    // --- Step 1: Compute Wallet Beta address ---
    let pubkey = |secret: &str| -> String {
        let bytes: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&bytes)
                .verifying_key()
                .as_bytes(),
        )
    };

    let beta_params = DeployParams {
        agent_pubkey: pubkey(&agent_beta),
        controller_pubkey: pubkey(&ctrl_beta),
        owner_pubkey: pubkey(&owner),
        initial_value: 500_000_000,
    };

    let beta_deploy = prepare_deploy(&beta_params, &agent_beta)?;
    println!("Wallet Beta address: {}", beta_deploy.address);

    // --- Step 2: Fund Wallet Beta from Alpha (must be funded before deploy) ---
    println!("\n[Step 2] Funding Wallet Beta from Alpha (200 VMSHELL)...");
    let fund_params = serde_json::json!({
        "dest": beta_deploy.address,
        "value": "200000000000",  // 200 VMSHELL
        "cc": {},
        "bounce": false,  // don't bounce — account doesn't exist yet
        "flag": 1,
        "payload": "",
    });
    let fund_boc = encode_call(ALPHA_ADDR, "submitTransaction", &fund_params, &agent_alpha)?;
    let fund_resp = send_message(&http, ENDPOINT, &fund_boc).await?;
    let fund_trans_id = extract_trans_id(&fund_resp)?;
    println!("  Submit OK, transId={fund_trans_id}");

    // Confirm from controller
    let confirm_boc = encode_call(
        ALPHA_ADDR,
        "confirmTransaction",
        &serde_json::json!({"transactionId": fund_trans_id.to_string()}),
        &ctrl_alpha,
    )?;
    let confirm_resp = send_message(&http, ENDPOINT, &confirm_boc).await?;
    check_result("Fund confirm", &confirm_resp)?;

    // Wait for funding to settle
    println!("  Waiting 3s for funding to settle...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // --- Step 3: Deploy Wallet Beta (now funded) ---
    println!("\n[Step 3] Deploying Wallet Beta...");
    let deploy_resp = send_message(&http, ENDPOINT, &beta_deploy.message_boc_base64).await?;
    let deploy_exit = deploy_resp["result"]["exit_code"].as_i64();
    if deploy_exit == Some(0) {
        println!("  Wallet Beta deployed! exit_code=0");
    } else {
        println!(
            "  Deploy response: {}",
            serde_json::to_string_pretty(&deploy_resp)?
        );
    }

    // --- Step 4: Beta pays Alpha 50 VMSHELL for "research data" ---
    println!("\n[Step 4] Beta pays Alpha 50 VMSHELL for research data...");
    let pay_params = serde_json::json!({
        "dest": ALPHA_ADDR,
        "value": "50000000000",  // 50 VMSHELL
        "cc": {},
        "bounce": true,
        "flag": 1,
        "payload": "",
    });
    let pay_boc = encode_call(
        &beta_deploy.address,
        "submitTransaction",
        &pay_params,
        &agent_beta,
    )?;
    let pay_resp = send_message(&http, ENDPOINT, &pay_boc).await?;
    let pay_trans_id = extract_trans_id(&pay_resp)?;
    println!("  Submit OK, transId={pay_trans_id}");

    // Controller Beta confirms
    let confirm2_boc = encode_call(
        &beta_deploy.address,
        "confirmTransaction",
        &serde_json::json!({"transactionId": pay_trans_id.to_string()}),
        &ctrl_beta,
    )?;
    let confirm2_resp = send_message(&http, ENDPOINT, &confirm2_boc).await?;
    check_result("Payment Beta→Alpha", &confirm2_resp)?;

    // --- Step 5: Alpha pays Beta 20 VMSHELL for "data quality review" ---
    println!("\n[Step 5] Alpha pays Beta 20 VMSHELL for data quality review...");
    let review_params = serde_json::json!({
        "dest": beta_deploy.address,
        "value": "20000000000",  // 20 VMSHELL
        "cc": {},
        "bounce": true,
        "flag": 1,
        "payload": "",
    });
    let review_boc = encode_call(
        ALPHA_ADDR,
        "submitTransaction",
        &review_params,
        &agent_alpha,
    )?;
    let review_resp = send_message(&http, ENDPOINT, &review_boc).await?;
    let review_trans_id = extract_trans_id(&review_resp)?;
    println!("  Submit OK, transId={review_trans_id}");

    let confirm3_boc = encode_call(
        ALPHA_ADDR,
        "confirmTransaction",
        &serde_json::json!({"transactionId": review_trans_id.to_string()}),
        &ctrl_alpha,
    )?;
    let confirm3_resp = send_message(&http, ENDPOINT, &confirm3_boc).await?;
    check_result("Payment Alpha→Beta", &confirm3_resp)?;

    // --- Step 6: Check balances ---
    println!("\n[Step 6] Checking balances...");
    let alpha_bal = get_balance(ALPHA_ADDR).await?;
    let beta_bal = get_balance(&beta_deploy.address).await?;
    println!("  Alpha balance: {} nanotoken", alpha_bal);
    println!("  Beta balance:  {} nanotoken", beta_bal);

    println!("\n=== E2E Test Complete ===");
    println!("Transactions executed:");
    println!("  1. Deploy Wallet Beta");
    println!("  2. Alpha → Beta: 100 VMSHELL (funding)");
    println!("  3. Beta → Alpha: 50 VMSHELL (research data payment)");
    println!("  4. Alpha → Beta: 20 VMSHELL (quality review payment)");
    println!("\nAll with 2-of-3 multisig (agent submit + controller confirm).");
    println!("Events should appear in gosh.memory via block stream.");

    Ok(())
}

fn extract_trans_id(resp: &serde_json::Value) -> anyhow::Result<u64> {
    use tvm_block::Deserializable;

    let exit_code = resp["result"]["exit_code"].as_i64();
    if exit_code != Some(0) {
        anyhow::bail!("tx failed: {}", serde_json::to_string_pretty(resp)?);
    }

    let ext_out = resp["result"]["ext_out_msgs"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no ext_out_msg"))?;

    use base64::Engine;
    let boc = base64::engine::general_purpose::STANDARD.decode(ext_out)?;
    let cell = tvm_types::read_single_root_boc(&boc).map_err(|e| anyhow::anyhow!("{e}"))?;
    let msg = tvm_block::Message::construct_from_cell(cell).map_err(|e| anyhow::anyhow!("{e}"))?;
    let body = msg.body().ok_or_else(|| anyhow::anyhow!("no body"))?;

    let abi = &*MULTISIG_ABI;
    let func = abi
        .function("submitTransaction")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let tokens = func
        .decode_output(body, false, true)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    for token in &tokens {
        if token.name == "transId" {
            if let tvm_abi::TokenValue::Uint(v) = &token.value {
                return Ok(v.number.to_u64_digits().first().copied().unwrap_or(0));
            }
        }
    }
    anyhow::bail!("transId not found")
}

fn check_result(label: &str, resp: &serde_json::Value) -> anyhow::Result<()> {
    let exit_code = resp["result"]["exit_code"].as_i64();
    let aborted = resp["result"]["aborted"].as_bool();
    if exit_code == Some(0) && aborted == Some(false) {
        println!("  {label}: OK");
        Ok(())
    } else {
        anyhow::bail!("{label}: FAILED — {}", serde_json::to_string_pretty(resp)?)
    }
}

async fn get_balance(addr: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::new();
    let resp = client
        .post("https://shellnet.ackinacki.org/graphql")
        .json(&serde_json::json!({
            "query": format!(
                "{{ blockchain {{ account(address: \"{addr}\") {{ info {{ balance }} }} }} }}"
            )
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let balance = resp["data"]["blockchain"]["account"]["info"]["balance"]
        .as_str()
        .unwrap_or("unknown");
    // Convert hex to decimal
    let bal = u128::from_str_radix(balance.trim_start_matches("0x"), 16).unwrap_or(0);
    Ok(bal.to_string())
}

fn encode_call(
    addr_str: &str,
    function_name: &str,
    params: &serde_json::Value,
    secret: &str,
) -> anyhow::Result<String> {
    let parts: Vec<&str> = addr_str.splitn(2, ':').collect();
    let wc: i8 = parts[0].parse()?;
    let bytes = hex::decode(parts[1])?;
    let address = tvm_block::MsgAddressInt::with_standart(
        None,
        wc,
        tvm_types::AccountId::from_raw(bytes, 256),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let signer_bytes = hex::decode(secret)?;
    let signer_key = ed25519_dalek::SigningKey::from_bytes(
        &signer_bytes
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("key"))?,
    );

    let abi = &*MULTISIG_ABI;
    let function = abi
        .function(function_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let header = serde_json::json!({
        "pubkey": hex::encode(signer_key.verifying_key().as_bytes()),
        "time": now,
        "expire": (now / 1000) + 300,
    });

    let header_tokens = Tokenizer::tokenize_optional_params(function.header_params(), &header)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let input_tokens = Tokenizer::tokenize_all_params(function.input_params(), params)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let sign_key =
        tvm_types::ed25519_create_private_key(&signer_bytes).map_err(|e| anyhow::anyhow!("{e}"))?;

    let body = function
        .encode_input(
            &header_tokens,
            &input_tokens,
            false,
            Some(&sign_key),
            Some(address.clone()),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let body_slice =
        tvm_types::SliceData::load_builder(body).map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut msg = tvm_block::Message::with_ext_in_header(tvm_block::ExternalInboundMessageHeader {
        src: tvm_block::MsgAddressExt::default(),
        dst: address,
        import_fee: Default::default(),
    });
    msg.set_body(body_slice);

    let msg_cell = msg.serialize().map_err(|e| anyhow::anyhow!("{e}"))?;
    let boc = tvm_types::write_boc(&msg_cell).map_err(|e| anyhow::anyhow!("{e}"))?;

    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&boc))
}
