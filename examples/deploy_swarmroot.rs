//! Deploy SwarmRoot on shellnet, setWalletCode, then deploy a child multisig.

use gosh_ackinacki::wallet::query::send_message;
use tvm_abi::token::Tokenizer;
use tvm_block::{Deserializable, Serializable};

const ENDPOINT: &str = "https://shellnet.ackinacki.org";

const SWARMROOT_ABI: &str = include_str!("../contracts/swarm/SwarmRoot.abi.json");
const SWARMROOT_TVC: &[u8] = include_bytes!("../contracts/swarm/SwarmRoot.tvc");
const WALLET_TVC: &[u8] = include_bytes!("../contracts/swarm/SwarmMultisigWallet.tvc");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let owner_secret = std::env::var("OWNER_SECRET").expect("set OWNER_SECRET");
    let http = reqwest::Client::new();

    let owner_bytes: [u8; 32] = hex::decode(&owner_secret)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("key"))?;
    let owner_key = ed25519_dalek::SigningKey::from_bytes(&owner_bytes);
    let owner_pubkey = hex::encode(owner_key.verifying_key().as_bytes());

    println!("=== Deploy SwarmRoot ===\n");
    println!("Owner pubkey: {owner_pubkey}");

    // Step 1: Deploy SwarmRoot
    println!("\n[1] Deploying SwarmRoot...");
    let abi = tvm_abi::Contract::load(SWARMROOT_ABI.as_bytes())
        .map_err(|e| anyhow::anyhow!("ABI: {e}"))?;

    let tvc_cell =
        tvm_types::read_single_root_boc(SWARMROOT_TVC).map_err(|e| anyhow::anyhow!("TVC: {e}"))?;
    let mut state_init = tvm_block::StateInit::construct_from_cell(tvc_cell)
        .map_err(|e| anyhow::anyhow!("StateInit: {e}"))?;

    // Set pubkey in data
    let pubkey_bytes = owner_key.verifying_key().to_bytes();
    let data = state_init.data.clone().unwrap_or_default();
    let mut data_slice =
        tvm_types::SliceData::load_cell(data).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut builder = tvm_types::BuilderData::new();
    builder
        .append_raw(&pubkey_bytes, 256)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if data_slice.remaining_bits() >= 256 {
        data_slice
            .get_next_bits(256)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    if data_slice.remaining_bits() > 0 || data_slice.remaining_references() > 0 {
        builder
            .checked_append_references_and_data(&data_slice)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    state_init.set_data(builder.into_cell().map_err(|e| anyhow::anyhow!("{e}"))?);

    let si_cell = state_init.serialize().map_err(|e| anyhow::anyhow!("{e}"))?;
    let address = format!("0:{}", hex::encode(si_cell.repr_hash().as_slice()));
    let address_int = tvm_block::MsgAddressInt::with_standart(
        None,
        0,
        tvm_types::AccountId::from(si_cell.repr_hash()),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("  SwarmRoot address: {address}");

    // Fund SwarmRoot from Alpha wallet first
    println!("\n[1a] Funding SwarmRoot from Alpha...");
    let alpha_addr = "0:03079cdd1f5c3044fb3f7993becb2f581ffc1e3d128db4afc411e7870af883c3";
    let agent_alpha = std::env::var("AGENT_ALPHA_SECRET").expect("set AGENT_ALPHA_SECRET");
    let ctrl_alpha = std::env::var("CTRL_ALPHA_SECRET").expect("set CTRL_ALPHA_SECRET");

    let fund_params = serde_json::json!({
        "dest": address,
        "value": "0",
        "cc": {"2": "10000000000"},  // 10 SHELL (ECC currency 2)
        "bounce": false,
        "flag": 17,  // 1 + 16: pay fees separately + convert SHELL→VMSHELL on uninit
        "payload": "",
    });
    let fund_boc = encode_call(alpha_addr, "submitTransaction", &fund_params, &agent_alpha)?;
    let fund_resp = send_message(&http, ENDPOINT, &fund_boc).await?;
    if fund_resp["result"]["exit_code"].as_i64() != Some(0) {
        anyhow::bail!(
            "fund submit failed: {}",
            serde_json::to_string_pretty(&fund_resp)?
        );
    }
    let trans_id = extract_trans_id(&fund_resp)?;
    let confirm_boc = encode_call(
        alpha_addr,
        "confirmTransaction",
        &serde_json::json!({"transactionId": trans_id.to_string()}),
        &ctrl_alpha,
    )?;
    let confirm_resp = send_message(&http, ENDPOINT, &confirm_boc).await?;
    if confirm_resp["result"]["exit_code"].as_i64() != Some(0) {
        anyhow::bail!(
            "fund confirm failed: {}",
            serde_json::to_string_pretty(&confirm_resp)?
        );
    }
    println!("  Funded with 50 VMSHELL");

    // Wait for internal transfer to settle across threads
    println!("  Waiting 15s for cross-thread settlement...");
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;

    // Deploy SwarmRoot
    let constructor = abi
        .function("constructor")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let header = build_header(&owner_key);
    let ht = Tokenizer::tokenize_optional_params(constructor.header_params(), &header)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let it = Tokenizer::tokenize_all_params(constructor.input_params(), &serde_json::json!({}))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let sign =
        tvm_types::ed25519_create_private_key(&owner_bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
    let body = constructor
        .encode_input(&ht, &it, false, Some(&sign), Some(address_int.clone()))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let body_slice =
        tvm_types::SliceData::load_builder(body).map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut msg = tvm_block::Message::with_ext_in_header(tvm_block::ExternalInboundMessageHeader {
        src: tvm_block::MsgAddressExt::default(),
        dst: address_int.clone(),
        import_fee: Default::default(),
    });
    msg.set_state_init(state_init);
    msg.set_body(body_slice);

    let boc = tvm_types::write_boc(&msg.serialize().map_err(|e| anyhow::anyhow!("{e}"))?)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    use base64::Engine;
    let boc_b64 = base64::engine::general_purpose::STANDARD.encode(&boc);

    let deploy_resp = send_message(&http, ENDPOINT, &boc_b64).await?;
    if deploy_resp["result"]["exit_code"].as_i64() == Some(0) {
        println!("  SwarmRoot deployed!");
    } else {
        println!(
            "  Deploy response: {}",
            serde_json::to_string_pretty(&deploy_resp)?
        );
        return Ok(());
    }

    // Step 2: setWalletCode
    println!("\n[2] Setting wallet code...");
    // Extract code cell from TVC (StateInit → code)
    let wallet_tvc_cell = tvm_types::read_single_root_boc(WALLET_TVC)
        .map_err(|e| anyhow::anyhow!("read wallet TVC: {e}"))?;
    let wallet_si = tvm_block::StateInit::construct_from_cell(wallet_tvc_cell)
        .map_err(|e| anyhow::anyhow!("parse wallet StateInit: {e}"))?;
    let wallet_code_cell = wallet_si
        .code
        .ok_or_else(|| anyhow::anyhow!("no code in wallet TVC"))?;
    let wallet_boc = tvm_types::write_boc(&wallet_code_cell).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("  Wallet code size: {} bytes", wallet_boc.len());
    let wallet_b64 = base64::engine::general_purpose::STANDARD.encode(&wallet_boc);

    let set_code_boc = encode_swarmroot_call(
        &address,
        &abi,
        "setWalletCode",
        &serde_json::json!({"code": wallet_b64}),
        &owner_secret,
    )?;
    let set_resp = send_message(&http, ENDPOINT, &set_code_boc).await?;
    if set_resp["result"]["exit_code"].as_i64() == Some(0) {
        println!("  Wallet code set!");
    } else {
        println!(
            "  setWalletCode: {}",
            serde_json::to_string_pretty(&set_resp)?
        );
        return Ok(());
    }

    // Step 3: Create DappConfig for SwarmRoot DApp ID
    println!("\n[3] Creating DappConfig (sending SHELL to DappRoot)...");
    let dapp_root = "0:9999999999999999999999999999999999999999999999999999999999999999";
    let create_config_boc = encode_swarmroot_call(
        &address,
        &abi,
        "createDappConfig",
        &serde_json::json!({
            "dappRoot": dapp_root,
            "shellAmount": "5000000000",  // 5 SHELL for DappConfig gas pool
        }),
        &owner_secret,
    )?;
    let config_resp = send_message(&http, ENDPOINT, &create_config_boc).await?;
    if config_resp["result"]["exit_code"].as_i64() == Some(0) {
        println!("  DappConfig created!");
    } else {
        println!(
            "  createDappConfig: {}",
            serde_json::to_string_pretty(&config_resp)?
        );
        return Ok(());
    }

    // Step 4: Deploy a child wallet
    println!("\n[4] Deploying child multisig via SwarmRoot...");
    let child_pubkeys = vec![format!("0x{}", owner_pubkey)];
    let deploy_wallet_boc = encode_swarmroot_call(
        &address,
        &abi,
        "deployWallet",
        &serde_json::json!({
            "ownerPubkeys": child_pubkeys,
            "ownerAddresses": [],
            "reqConfirms": 1,
            "initialValue": "0",
            "walletPubkey": format!("0x{}", owner_pubkey),
        }),
        &owner_secret,
    )?;
    let wallet_resp = send_message(&http, ENDPOINT, &deploy_wallet_boc).await?;
    if wallet_resp["result"]["exit_code"].as_i64() == Some(0) {
        println!("  Child wallet deployed!");
        // Try to extract address from ext_out_msgs
        if let Some(ext_out) = wallet_resp["result"]["ext_out_msgs"]
            .as_array()
            .and_then(|a| a.first())
        {
            println!("  ext_out: {}", ext_out);
        }
    } else {
        println!(
            "  deployWallet: {}",
            serde_json::to_string_pretty(&wallet_resp)?
        );
    }

    println!("\n=== Done ===");
    println!("SwarmRoot: {address}");

    Ok(())
}

fn build_header(key: &ed25519_dalek::SigningKey) -> serde_json::Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    serde_json::json!({
        "pubkey": hex::encode(key.verifying_key().as_bytes()),
        "time": now,
        "expire": (now / 1000) + 300,
    })
}

fn extract_trans_id(resp: &serde_json::Value) -> anyhow::Result<u64> {
    use gosh_ackinacki::wallet::contracts::MULTISIG_ABI;
    let ext_out = resp["result"]["ext_out_msgs"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no ext_out"))?;
    use base64::Engine;
    let boc = base64::engine::general_purpose::STANDARD.decode(ext_out)?;
    let cell = tvm_types::read_single_root_boc(&boc).map_err(|e| anyhow::anyhow!("{e}"))?;
    let msg = tvm_block::Message::construct_from_cell(cell).map_err(|e| anyhow::anyhow!("{e}"))?;
    let body = msg.body().ok_or_else(|| anyhow::anyhow!("no body"))?;
    let func = MULTISIG_ABI
        .function("submitTransaction")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let tokens = func
        .decode_output(body, false, true)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    for t in &tokens {
        if t.name == "transId" {
            if let tvm_abi::TokenValue::Uint(v) = &t.value {
                return Ok(v.number.to_u64_digits().first().copied().unwrap_or(0));
            }
        }
    }
    anyhow::bail!("transId not found")
}

fn encode_call(
    addr: &str,
    func: &str,
    params: &serde_json::Value,
    secret: &str,
) -> anyhow::Result<String> {
    use gosh_ackinacki::wallet::contracts::MULTISIG_ABI;
    let parts: Vec<&str> = addr.splitn(2, ':').collect();
    let address = tvm_block::MsgAddressInt::with_standart(
        None,
        parts[0].parse()?,
        tvm_types::AccountId::from_raw(hex::decode(parts[1])?, 256),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let sb = hex::decode(secret)?;
    let sk = ed25519_dalek::SigningKey::from_bytes(
        &sb.clone().try_into().map_err(|_| anyhow::anyhow!("key"))?,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let header = serde_json::json!({"pubkey": hex::encode(sk.verifying_key().as_bytes()), "time": now, "expire": (now/1000)+300});
    let function = MULTISIG_ABI
        .function(func)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let ht = Tokenizer::tokenize_optional_params(function.header_params(), &header)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let it = Tokenizer::tokenize_all_params(function.input_params(), params)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let sign = tvm_types::ed25519_create_private_key(&sb).map_err(|e| anyhow::anyhow!("{e}"))?;
    let body = function
        .encode_input(&ht, &it, false, Some(&sign), Some(address.clone()))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let bs = tvm_types::SliceData::load_builder(body).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut msg = tvm_block::Message::with_ext_in_header(tvm_block::ExternalInboundMessageHeader {
        src: tvm_block::MsgAddressExt::default(),
        dst: address,
        import_fee: Default::default(),
    });
    msg.set_body(bs);
    let boc = tvm_types::write_boc(&msg.serialize().map_err(|e| anyhow::anyhow!("{e}"))?)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&boc))
}

fn encode_swarmroot_call(
    addr: &str,
    abi: &tvm_abi::Contract,
    func_name: &str,
    params: &serde_json::Value,
    secret: &str,
) -> anyhow::Result<String> {
    let parts: Vec<&str> = addr.splitn(2, ':').collect();
    let address = tvm_block::MsgAddressInt::with_standart(
        None,
        parts[0].parse()?,
        tvm_types::AccountId::from_raw(hex::decode(parts[1])?, 256),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let sb = hex::decode(secret)?;
    let sk = ed25519_dalek::SigningKey::from_bytes(
        &sb.clone().try_into().map_err(|_| anyhow::anyhow!("key"))?,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let header = serde_json::json!({"pubkey": hex::encode(sk.verifying_key().as_bytes()), "time": now, "expire": (now/1000)+300});
    let function = abi
        .function(func_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let ht = Tokenizer::tokenize_optional_params(function.header_params(), &header)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let it = Tokenizer::tokenize_all_params(function.input_params(), params)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let sign = tvm_types::ed25519_create_private_key(&sb).map_err(|e| anyhow::anyhow!("{e}"))?;
    let body = function
        .encode_input(&ht, &it, false, Some(&sign), Some(address.clone()))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let bs = tvm_types::SliceData::load_builder(body).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut msg = tvm_block::Message::with_ext_in_header(tvm_block::ExternalInboundMessageHeader {
        src: tvm_block::MsgAddressExt::default(),
        dst: address,
        import_fee: Default::default(),
    });
    msg.set_body(bs);
    let boc = tvm_types::write_boc(&msg.serialize().map_err(|e| anyhow::anyhow!("{e}"))?)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&boc))
}
