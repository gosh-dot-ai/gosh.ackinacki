//! Deploy DappConfig: submit from agent + confirm from controller in one go.

use gosh_ackinacki::wallet::contracts::MULTISIG_ABI;
use gosh_ackinacki::wallet::query::send_message;
use tvm_abi::token::Tokenizer;
use tvm_block::{Deserializable, Serializable};

const WALLET_ADDR: &str = "0:03079cdd1f5c3044fb3f7993becb2f581ffc1e3d128db4afc411e7870af883c3";
const DAPP_ROOT: &str = "0:9999999999999999999999999999999999999999999999999999999999999999";
const ENDPOINT: &str = "https://shellnet.ackinacki.org";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http = reqwest::Client::new();
    let agent_secret = std::env::var("AGENT_SECRET").expect("set AGENT_SECRET env var");
    let controller_secret =
        std::env::var("CONTROLLER_SECRET").expect("set CONTROLLER_SECRET env var");
    // Encode payload: DappRoot.deployNewConfigCustom(null)
    let dapproot_abi =
        tvm_abi::Contract::load(include_str!("../contracts/DappRoot.abi.json").as_bytes())
            .map_err(|e| anyhow::anyhow!("ABI: {e}"))?;

    let func = dapproot_abi
        .function("deployNewConfigCustom")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let input_tokens = Tokenizer::tokenize_all_params(
        func.input_params(),
        &serde_json::json!({"authorityAddress": null}),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let body_builder = func
        .encode_input(
            &std::collections::HashMap::new(),
            &input_tokens,
            true,
            None,
            None,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let payload_cell = body_builder
        .into_cell()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let payload_boc = tvm_types::write_boc(&payload_cell).map_err(|e| anyhow::anyhow!("{e}"))?;
    let payload_b64 = b64(&payload_boc);

    println!("Payload ready ({} bytes)", payload_boc.len());

    // Step 1: submitTransaction from agent
    let submit_params = serde_json::json!({
        "dest": DAPP_ROOT,
        "value": "1000000000",
        "cc": {"2": "200000000000"},
        "bounce": true,
        "flag": 1,
        "payload": payload_b64,
    });

    println!("Submitting from agent...");
    let submit_boc = encode_call(
        WALLET_ADDR,
        "submitTransaction",
        &submit_params,
        &agent_secret,
    )?;
    let submit_resp = send_message(&http, ENDPOINT, &submit_boc).await?;

    let exit_code = submit_resp["result"]["exit_code"].as_i64();
    if exit_code != Some(0) {
        println!(
            "Submit failed: {}",
            serde_json::to_string_pretty(&submit_resp)?
        );
        return Ok(());
    }

    // Decode transId from ext_out_msgs
    let ext_out = submit_resp["result"]["ext_out_msgs"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str());

    let trans_id = match ext_out {
        Some(msg_b64) => decode_trans_id(msg_b64)?,
        None => anyhow::bail!("no ext_out_msg in submit response"),
    };

    println!("Submit OK, transId={trans_id}");

    // Step 2: confirmTransaction from controller — immediately
    println!("Confirming from controller...");
    let confirm_params = serde_json::json!({
        "transactionId": trans_id.to_string(),
    });
    let confirm_boc = encode_call(
        WALLET_ADDR,
        "confirmTransaction",
        &confirm_params,
        &controller_secret,
    )?;
    let confirm_resp = send_message(&http, ENDPOINT, &confirm_boc).await?;

    let confirm_exit = confirm_resp["result"]["exit_code"].as_i64();
    if confirm_exit == Some(0) {
        println!("DappConfig deployed! Check on-chain.");
    } else {
        println!(
            "Confirm response: {}",
            serde_json::to_string_pretty(&confirm_resp)?
        );
    }

    Ok(())
}

fn decode_trans_id(ext_out_b64: &str) -> anyhow::Result<u64> {
    use base64::Engine;
    let boc = base64::engine::general_purpose::STANDARD.decode(ext_out_b64)?;

    // Parse the ext_out message to get the body
    let cell = tvm_types::read_single_root_boc(&boc).map_err(|e| anyhow::anyhow!("{e}"))?;
    let msg = tvm_block::Message::construct_from_cell(cell)
        .map_err(|e| anyhow::anyhow!("parse msg: {e}"))?;

    let body = msg
        .body()
        .ok_or_else(|| anyhow::anyhow!("no body in ext_out"))?;

    // submitTransaction output: function_id (32 bit) + uint64 transId
    let abi = &*MULTISIG_ABI;
    let func = abi
        .function("submitTransaction")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let tokens = func
        .decode_output(body, false, true)
        .map_err(|e| anyhow::anyhow!("decode output: {e}"))?;

    for token in &tokens {
        if token.name == "transId" {
            if let tvm_abi::TokenValue::Uint(v) = &token.value {
                return Ok(v.number.to_u64_digits().first().copied().unwrap_or(0));
            }
        }
    }

    anyhow::bail!("transId not found in output")
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
            .map_err(|_| anyhow::anyhow!("key len"))?,
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
        "expire": (now / 1000) + 300,  // 5 min expire
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
    Ok(b64(&boc))
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}
