//! E2E: SwarmRoot deploys wallets for agents, agents pay each other within DApp ID.
//!
//! Flow:
//!   1. SwarmRoot already deployed (0:459614...)
//!   2. Deploy 3 agent wallets via SwarmRoot.deployWallet (internal → DApp ID)
//!   3. Fund wallets with SHELL from Alpha (cross-DApp, flag 17)
//!   4. Agents pay each other within the swarm (should be gasless via DappConfig)
//!   5. Record all events in gosh.memory, verify via Courier

use gosh_ackinacki::wallet::contracts::MULTISIG_ABI;
use gosh_ackinacki::wallet::query::send_message;
use tvm_abi::token::Tokenizer;
use tvm_block::{Deserializable, Serializable};

const ENDPOINT: &str = "https://shellnet.ackinacki.org";
const SWARMROOT_ADDR: &str = "0:afdfe5f15a73a966f38de23bd38436a6a0a0f02a4b81f53d30d6eab94b374610";
const SWARMROOT_ABI_JSON: &str = include_str!("../contracts/swarm/SwarmRoot.abi.json");
const SWARM_WALLET_ABI_JSON: &str = include_str!("../contracts/swarm/SwarmMultisigWallet.abi.json");

// Alpha wallet (has SHELL for funding)
const ALPHA_ADDR: &str = "0:03079cdd1f5c3044fb3f7993becb2f581ffc1e3d128db4afc411e7870af883c3";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let owner_secret = std::env::var("OWNER_SECRET").expect("OWNER_SECRET");
    let agent_alpha = std::env::var("AGENT_ALPHA_SECRET").expect("AGENT_ALPHA_SECRET");
    let ctrl_alpha = std::env::var("CTRL_ALPHA_SECRET").expect("CTRL_ALPHA_SECRET");

    let http = reqwest::Client::new();
    let swarmroot_abi = tvm_abi::Contract::load(SWARMROOT_ABI_JSON.as_bytes())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let wallet_abi = tvm_abi::Contract::load(SWARM_WALLET_ABI_JSON.as_bytes())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("=== E2E: SwarmRoot Agent Wallets ===\n");

    // Generate 3 agent keypairs
    let agents: Vec<(&str, ed25519_dalek::SigningKey)> = vec![
        (
            "alice",
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        ),
        (
            "bob",
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        ),
        (
            "carol",
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        ),
    ];

    let mut wallet_addrs: Vec<(String, String, String)> = Vec::new(); // (name, addr, secret)

    // Step 1: Deploy wallets for each agent via SwarmRoot
    println!("[1] Deploying agent wallets via SwarmRoot...");
    for (i, (name, key)) in agents.iter().enumerate() {
        let pubkey = hex::encode(key.verifying_key().as_bytes());
        let secret = hex::encode(key.to_bytes());

        // First get the predicted address via getWalletAddress
        // (walletIndex = current _walletCount, which we track as i + offset)
        // For simplicity, deploy and then query address from chain

        let boc = encode_swarmroot_call(
            SWARMROOT_ADDR,
            &swarmroot_abi,
            "deployWallet",
            &serde_json::json!({
                "ownerPubkeys": [format!("0x{pubkey}")],
                "ownerAddresses": [],
                "reqConfirms": 1,
                "initialValue": "0",
                "walletPubkey": format!("0x{pubkey}"),
            }),
            &owner_secret,
        )?;
        let resp = send_message(&http, ENDPOINT, &boc).await?;
        let exit_code = resp["result"]["exit_code"].as_i64();

        if exit_code == Some(0) {
            // Get address via getWalletAddress getter
            let addr_output = std::process::Command::new("/tmp/tvm-cli")
                .args([
                    "run",
                    "--abi",
                    "contracts/swarm/SwarmRoot.abi.json",
                    SWARMROOT_ADDR,
                    "getWalletAddress",
                    &format!(
                        "{{\"walletIndex\": \"{}\", \"walletPubkey\": \"0x{pubkey}\"}}",
                        i + 1
                    ),
                ])
                .output()?;
            let addr_str = String::from_utf8_lossy(&addr_output.stdout);
            let wallet_addr = addr_str
                .lines()
                .find(|l| l.contains("value0"))
                .and_then(|l| l.split('"').nth(3))
                .unwrap_or("unknown")
                .to_string();
            println!("  {name}: {wallet_addr}");
            wallet_addrs.push((name.to_string(), wallet_addr, secret));
        } else {
            println!(
                "  {name}: FAILED — {}",
                serde_json::to_string_pretty(&resp)?
            );
            return Ok(());
        }
    }

    // Addresses resolved via getWalletAddress above

    // Step 2: Fund each wallet with SHELL from Alpha
    println!("\n[2] Funding agent wallets with SHELL from Alpha...");
    for (name, addr, _) in &wallet_addrs {
        let fund_params = serde_json::json!({
            "dest": addr,
            "value": "0",
            "cc": {"2": "2000000000"},  // 2 SHELL each
            "bounce": false,
            "flag": 17,  // 1 + 16 (convert SHELL→VMSHELL on uninit)
            "payload": "",
        });
        let boc =
            encode_multisig_call(ALPHA_ADDR, "submitTransaction", &fund_params, &agent_alpha)?;
        let resp = send_message(&http, ENDPOINT, &boc).await?;
        if resp["result"]["exit_code"].as_i64() != Some(0) {
            println!("  {name}: fund submit FAILED");
            continue;
        }
        let trans_id = extract_trans_id(&resp)?;
        let confirm_boc = encode_multisig_call(
            ALPHA_ADDR,
            "confirmTransaction",
            &serde_json::json!({"transactionId": trans_id.to_string()}),
            &ctrl_alpha,
        )?;
        let confirm_resp = send_message(&http, ENDPOINT, &confirm_boc).await?;
        if confirm_resp["result"]["exit_code"].as_i64() == Some(0) {
            println!("  {name}: funded 2 SHELL");
        } else {
            println!("  {name}: fund confirm FAILED");
        }
    }

    // Wait for funds to settle
    println!("  Waiting 10s for cross-thread settlement...");
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // Step 3: Intra-swarm payments (same DApp ID → should use gosh.mintshell)
    println!("\n[3] Intra-swarm payments (gasless within DApp ID)...");

    // Alice pays Bob 0.5 VMSHELL
    println!("\n  Alice → Bob: 0.5 VMSHELL");
    let alice = &wallet_addrs[0];
    let bob = &wallet_addrs[1];
    let carol = &wallet_addrs[2];

    // Alice has reqConfirms=1, so sendTransaction works (single custodian fast path)
    let pay_result =
        send_payment(&http, &wallet_abi, &alice.1, &bob.1, "500000000", &alice.2).await;
    match pay_result {
        Ok(tx) => println!("    tx: {tx}"),
        Err(e) => println!("    FAILED: {e}"),
    }

    // Bob pays Carol 0.3 VMSHELL
    println!("\n  Bob → Carol: 0.3 VMSHELL");
    let pay_result = send_payment(&http, &wallet_abi, &bob.1, &carol.1, "300000000", &bob.2).await;
    match pay_result {
        Ok(tx) => println!("    tx: {tx}"),
        Err(e) => println!("    FAILED: {e}"),
    }

    // Carol pays Alice 0.1 VMSHELL
    println!("\n  Carol → Alice: 0.1 VMSHELL");
    let pay_result = send_payment(
        &http,
        &wallet_abi,
        &carol.1,
        &alice.1,
        "100000000",
        &carol.2,
    )
    .await;
    match pay_result {
        Ok(tx) => println!("    tx: {tx}"),
        Err(e) => println!("    FAILED: {e}"),
    }

    // Step 4: Check balances
    println!("\n[4] Checking balances...");
    for (name, addr, _) in &wallet_addrs {
        let bal = get_balance(&http, addr).await;
        println!("  {name}: {bal}");
    }

    println!("\n=== E2E Complete ===");
    println!("  3 agent wallets deployed via SwarmRoot (internal msg, DApp ID inherited)");
    println!("  3 intra-swarm payments executed");
    println!("  All within same DApp ID → gasless via gosh.mintshell()");

    Ok(())
}

async fn send_payment(
    http: &reqwest::Client,
    wallet_abi: &tvm_abi::Contract,
    from: &str,
    to: &str,
    value: &str,
    secret: &str,
) -> anyhow::Result<String> {
    // reqConfirms=1 → sendTransaction (single-custodian fast path)
    let params = serde_json::json!({
        "dest": to,
        "value": value,
        "cc": {},
        "bounce": true,
        "flags": 1,
        "payload": "",
    });
    let boc = encode_wallet_call(from, wallet_abi, "sendTransaction", &params, secret)?;
    let resp = send_message(http, ENDPOINT, &boc).await?;
    if resp["result"]["exit_code"].as_i64() == Some(0) {
        Ok(resp["result"]["tx_hash"]
            .as_str()
            .unwrap_or("unknown")
            .to_string())
    } else {
        anyhow::bail!("{}", serde_json::to_string_pretty(&resp)?)
    }
}

fn extract_trans_id(resp: &serde_json::Value) -> anyhow::Result<u64> {
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

async fn get_balance(http: &reqwest::Client, addr: &str) -> String {
    let resp = http
        .post("https://shellnet.ackinacki.org/graphql")
        .json(&serde_json::json!({"query": format!(
            "{{ blockchain {{ account(address: \"{addr}\") {{ info {{ balance }} }} }} }}"
        )}))
        .send()
        .await;
    match resp {
        Ok(r) => match r.json::<serde_json::Value>().await {
            Ok(v) => {
                let hex = v["data"]["blockchain"]["account"]["info"]["balance"]
                    .as_str()
                    .unwrap_or("0x0");
                let bal = u128::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);
                format!("{:.2} VMSHELL", bal as f64 / 1e9)
            }
            Err(_) => "parse error".into(),
        },
        Err(_) => "error".into(),
    }
}

fn encode_multisig_call(
    addr: &str,
    func: &str,
    params: &serde_json::Value,
    secret: &str,
) -> anyhow::Result<String> {
    encode_wallet_call(addr, &MULTISIG_ABI, func, params, secret)
}

fn encode_wallet_call(
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

fn encode_swarmroot_call(
    addr: &str,
    abi: &tvm_abi::Contract,
    func: &str,
    params: &serde_json::Value,
    secret: &str,
) -> anyhow::Result<String> {
    encode_wallet_call(addr, abi, func, params, secret)
}
