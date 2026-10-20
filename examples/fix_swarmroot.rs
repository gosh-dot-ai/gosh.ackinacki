use gosh_ackinacki::wallet::query::send_message;
use tvm_abi::token::Tokenizer;
use tvm_block::{Deserializable, Serializable};

const ENDPOINT: &str = "https://shellnet.ackinacki.org";
const SWARMROOT_ABI: &str = include_str!("../contracts/swarm/SwarmRoot.abi.json");
const SWARMROOT_ADDR: &str = "0:459614c85fb2e3ca3ec1a6851c64b5ab6895c6bb04a6947d8d629b4bfc4aa5f7";
const WALLET_TVC: &[u8] = include_bytes!("../contracts/swarm/SwarmMultisigWallet.tvc");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let owner_secret = std::env::var("OWNER_SECRET").expect("OWNER_SECRET");
    let http = reqwest::Client::new();
    let abi =
        tvm_abi::Contract::load(SWARMROOT_ABI.as_bytes()).map_err(|e| anyhow::anyhow!("{e}"))?;

    let owner_bytes: [u8; 32] = hex::decode(&owner_secret)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("key"))?;
    let owner_key = ed25519_dalek::SigningKey::from_bytes(&owner_bytes);
    let owner_pubkey = hex::encode(owner_key.verifying_key().as_bytes());

    // Extract code cell from TVC
    let tvc_cell =
        tvm_types::read_single_root_boc(WALLET_TVC).map_err(|e| anyhow::anyhow!("{e}"))?;
    let si =
        tvm_block::StateInit::construct_from_cell(tvc_cell).map_err(|e| anyhow::anyhow!("{e}"))?;
    let code_cell = si.code.ok_or_else(|| anyhow::anyhow!("no code"))?;
    let code_boc = tvm_types::write_boc(&code_cell).map_err(|e| anyhow::anyhow!("{e}"))?;
    use base64::Engine;
    let code_b64 = base64::engine::general_purpose::STANDARD.encode(&code_boc);
    println!(
        "Wallet code: {} bytes BOC, {} b64 chars",
        code_boc.len(),
        code_b64.len()
    );

    // Step 1: setWalletCode with EXTRACTED code
    println!("\n[1] setWalletCode with extracted code cell...");
    let boc = encode_call(
        SWARMROOT_ADDR,
        &abi,
        "setWalletCode",
        &serde_json::json!({"code": code_b64}),
        &owner_secret,
    )?;
    let resp = send_message(&http, ENDPOINT, &boc).await?;
    println!("  exit_code: {:?}", resp["result"]["exit_code"].as_i64());

    // Step 2: deployWallet
    println!("\n[2] deployWallet...");
    let boc2 = encode_call(
        SWARMROOT_ADDR,
        &abi,
        "deployWallet",
        &serde_json::json!({
            "ownerPubkeys": [format!("0x{owner_pubkey}")],
            "ownerAddresses": [],
            "reqConfirms": 1,
            "initialValue": "0",
            "walletPubkey": format!("0x{owner_pubkey}"),
        }),
        &owner_secret,
    )?;
    let resp2 = send_message(&http, ENDPOINT, &boc2).await?;
    println!("  {}", serde_json::to_string_pretty(&resp2)?);

    Ok(())
}

fn encode_call(
    addr: &str,
    abi: &tvm_abi::Contract,
    func: &str,
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
    let function = abi.function(func).map_err(|e| anyhow::anyhow!("{e}"))?;
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
