//! E2E test: cross-swarm payments between two deployed multisig wallets.
//!
//! Alpha and Beta are already deployed on shellnet.
//! This test executes payments back and forth with 2-of-3 confirmation.

use gosh_ackinacki::wallet::contracts::MULTISIG_ABI;
use gosh_ackinacki::wallet::query::send_message;
use tvm_abi::token::Tokenizer;
use tvm_block::{Deserializable, Serializable};

const ENDPOINT: &str = "https://shellnet.ackinacki.org";
const ALPHA_ADDR: &str = "0:03079cdd1f5c3044fb3f7993becb2f581ffc1e3d128db4afc411e7870af883c3";
const BETA_ADDR: &str = "0:b924813593bb4963f9dbbd383b5ba43e118c7ce675a657619e251ed1c81dd754";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let agent_alpha = std::env::var("AGENT_ALPHA_SECRET").expect("set AGENT_ALPHA_SECRET");
    let ctrl_alpha = std::env::var("CTRL_ALPHA_SECRET").expect("set CTRL_ALPHA_SECRET");
    let agent_beta = std::env::var("AGENT_BETA_SECRET").expect("set AGENT_BETA_SECRET");
    let ctrl_beta = std::env::var("CTRL_BETA_SECRET").expect("set CTRL_BETA_SECRET");

    let http = reqwest::Client::new();

    println!("=== Cross-Swarm Payment E2E ===\n");

    // Check initial balances
    println!("[Balances before]");
    print_balance("Alpha", ALPHA_ADDR).await;
    print_balance("Beta", BETA_ADDR).await;

    // Payment 1: Alpha pays Beta 10 VMSHELL for "research data"
    println!("\n[Payment 1] Alpha → Beta: 10 VMSHELL (research data)");
    let tx1 = submit_and_confirm(
        ALPHA_ADDR,
        BETA_ADDR,
        "10000000000",
        &agent_alpha,
        &ctrl_alpha,
        &http,
    )
    .await?;
    println!("  tx_hash: {}", tx1);

    // Payment 2: Beta pays Alpha 5 VMSHELL for "data quality audit"
    println!("\n[Payment 2] Beta → Alpha: 5 VMSHELL (data quality audit)");
    let tx2 = submit_and_confirm(
        BETA_ADDR,
        ALPHA_ADDR,
        "5000000000",
        &agent_beta,
        &ctrl_beta,
        &http,
    )
    .await?;
    println!("  tx_hash: {}", tx2);

    // Payment 3: Alpha pays Beta 3 VMSHELL for "analysis report"
    println!("\n[Payment 3] Alpha → Beta: 3 VMSHELL (analysis report)");
    let tx3 = submit_and_confirm(
        ALPHA_ADDR,
        BETA_ADDR,
        "3000000000",
        &agent_alpha,
        &ctrl_alpha,
        &http,
    )
    .await?;
    println!("  tx_hash: {}", tx3);

    // Check final balances
    println!("\n[Balances after]");
    print_balance("Alpha", ALPHA_ADDR).await;
    print_balance("Beta", BETA_ADDR).await;

    println!("\n=== E2E Complete ===");
    println!("3 cross-swarm payments executed with 2-of-3 multisig confirmation.");
    Ok(())
}

async fn submit_and_confirm(
    from: &str,
    to: &str,
    value: &str,
    agent_secret: &str,
    ctrl_secret: &str,
    http: &reqwest::Client,
) -> anyhow::Result<String> {
    let params = serde_json::json!({
        "dest": to,
        "value": value,
        "cc": {},
        "bounce": true,
        "flag": 1,
        "payload": "",
    });

    // Submit
    let boc = encode_call(from, "submitTransaction", &params, agent_secret)?;
    let resp = send_message(http, ENDPOINT, &boc).await?;
    let exit_code = resp["result"]["exit_code"].as_i64();
    if exit_code != Some(0) {
        anyhow::bail!("submit failed: {}", serde_json::to_string_pretty(&resp)?);
    }
    let trans_id = extract_trans_id(&resp)?;
    println!("  submit OK, transId={trans_id}");

    // Confirm
    let confirm_params = serde_json::json!({"transactionId": trans_id.to_string()});
    let confirm_boc = encode_call(from, "confirmTransaction", &confirm_params, ctrl_secret)?;
    let confirm_resp = send_message(http, ENDPOINT, &confirm_boc).await?;
    let confirm_exit = confirm_resp["result"]["exit_code"].as_i64();
    if confirm_exit != Some(0) {
        anyhow::bail!(
            "confirm failed: {}",
            serde_json::to_string_pretty(&confirm_resp)?
        );
    }
    println!("  confirm OK");

    let tx_hash = confirm_resp["result"]["tx_hash"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    Ok(tx_hash)
}

fn extract_trans_id(resp: &serde_json::Value) -> anyhow::Result<u64> {
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

async fn print_balance(name: &str, addr: &str) {
    match get_balance(addr).await {
        Ok(bal) => println!(
            "  {name}: {bal} nanotoken ({:.2} VMSHELL)",
            bal as f64 / 1e9
        ),
        Err(e) => println!("  {name}: error: {e}"),
    }
}

async fn get_balance(addr: &str) -> anyhow::Result<u128> {
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

    let hex_bal = resp["data"]["blockchain"]["account"]["info"]["balance"]
        .as_str()
        .unwrap_or("0x0");
    Ok(u128::from_str_radix(hex_bal.trim_start_matches("0x"), 16).unwrap_or(0))
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
