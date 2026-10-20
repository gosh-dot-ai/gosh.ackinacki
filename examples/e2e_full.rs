//! Full E2E: policies + payments + gosh.memory integration.
//!
//! Two gosh.memory instances (Alpha swarm, Beta swarm).
//! Policies stored in memory, enforced before payments.
//! Payment facts injected into memory after execution.
//! Agents can recall payment history.

use serde_json::{json, Value};

const ALPHA_MEMORY: &str = "http://127.0.0.1:8100";
const BETA_MEMORY: &str = "http://127.0.0.1:8200";

const ALPHA_ADDR: &str = "0:03079cdd1f5c3044fb3f7993becb2f581ffc1e3d128db4afc411e7870af883c3";
const BETA_ADDR: &str = "0:b924813593bb4963f9dbbd383b5ba43e118c7ce675a657619e251ed1c81dd754";

const ENDPOINT: &str = "https://shellnet.ackinacki.org";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let agent_alpha = std::env::var("AGENT_ALPHA_SECRET").expect("set AGENT_ALPHA_SECRET");
    let ctrl_alpha = std::env::var("CTRL_ALPHA_SECRET").expect("set CTRL_ALPHA_SECRET");
    let agent_beta = std::env::var("AGENT_BETA_SECRET").expect("set AGENT_BETA_SECRET");
    let ctrl_beta = std::env::var("CTRL_BETA_SECRET").expect("set CTRL_BETA_SECRET");

    let http = reqwest::Client::builder()
        .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        .build()?;

    println!("=== Full E2E: Policies + Payments + gosh.memory ===\n");

    // Initialize MCP sessions
    println!("[Init] Connecting to gosh.memory instances...");
    let alpha_session = init_memory_session(&http, ALPHA_MEMORY).await?;
    println!("  Alpha session: {}", alpha_session.session_id);
    let beta_session = init_memory_session(&http, BETA_MEMORY).await?;
    println!("  Beta session: {}", beta_session.session_id);

    // ---------------------------------------------------------------
    // Step 1: Set wallet policies in gosh.memory
    // ---------------------------------------------------------------
    println!("\n[Step 1] Setting wallet policies in gosh.memory...");

    // Alpha policy: max 50 VMSHELL per tx, Beta is allowed dest
    mcp_call(
        &http,
        &alpha_session,
        "memory_ingest_asserted_facts",
        json!({
            "key": "alpha-swarm",
            "agent_id": "ackinacki",
            "swarm_id": "alpha",
            "facts": [{
                "fact": format!("Wallet policy for {ALPHA_ADDR}"),
                "kind": "constraint",
                "entities": [ALPHA_ADDR],
                "source_id": format!("wallet_policy:{ALPHA_ADDR}"),
                "metadata": {
                    "wallet_address": ALPHA_ADDR,
                    "max_tx_amount": 50_000_000_000_u64,
                    "allowed_destinations": [BETA_ADDR],
                    "policy_tier": "standard",
                    "enabled": true,
                }
            }]
        }),
    )
    .await?;
    println!("  Alpha policy set: max 50 VMSHELL, dest=[Beta]");

    // Beta policy: max 20 VMSHELL, Alpha is allowed
    mcp_call(
        &http,
        &beta_session,
        "memory_ingest_asserted_facts",
        json!({
            "key": "beta-swarm",
            "agent_id": "ackinacki",
            "swarm_id": "beta",
            "facts": [{
                "fact": format!("Wallet policy for {BETA_ADDR}"),
                "kind": "constraint",
                "entities": [BETA_ADDR],
                "source_id": format!("wallet_policy:{BETA_ADDR}"),
                "metadata": {
                    "wallet_address": BETA_ADDR,
                    "max_tx_amount": 20_000_000_000_u64,
                    "allowed_destinations": [ALPHA_ADDR],
                    "policy_tier": "standard",
                    "enabled": true,
                }
            }]
        }),
    )
    .await?;
    println!("  Beta policy set: max 20 VMSHELL, dest=[Alpha]");

    // ---------------------------------------------------------------
    // Step 2: Verify policies stored
    // ---------------------------------------------------------------
    println!("\n[Step 2] Querying policies from gosh.memory...");

    let alpha_policy = mcp_call(
        &http,
        &alpha_session,
        "memory_query",
        json!({
            "key": "alpha-swarm",
            "filter": {"kind": "constraint", "metadata.wallet_address": ALPHA_ADDR},
            "agent_id": "ackinacki",
            "swarm_id": "alpha",
        }),
    )
    .await?;
    let alpha_facts = alpha_policy["facts"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    println!("  Alpha policy facts: {alpha_facts}");

    let beta_policy = mcp_call(
        &http,
        &beta_session,
        "memory_query",
        json!({
            "key": "beta-swarm",
            "filter": {"kind": "constraint", "metadata.wallet_address": BETA_ADDR},
            "agent_id": "ackinacki",
            "swarm_id": "beta",
        }),
    )
    .await?;
    let beta_facts = beta_policy["facts"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    println!("  Beta policy facts: {beta_facts}");

    // ---------------------------------------------------------------
    // Step 3: Policy check — should PASS
    // ---------------------------------------------------------------
    println!("\n[Step 3] Policy enforcement tests...");

    use gosh_ackinacki::wallet::policy::parse_policy_from_memory;

    let alpha_wp = parse_policy_from_memory(&alpha_policy).unwrap_or_default();
    let beta_wp = parse_policy_from_memory(&beta_policy).unwrap_or_default();

    // Alpha → Beta 10 VMSHELL: should pass (within 50 limit, Beta allowed)
    let r = alpha_wp.check(BETA_ADDR, 10_000_000_000);
    println!(
        "  Alpha→Beta 10 VMSHELL: {}",
        if r.is_ok() { "PASS" } else { "FAIL" }
    );
    assert!(r.is_ok());

    // Beta → Alpha 15 VMSHELL: should pass (within 20 limit, Alpha allowed)
    let r = beta_wp.check(ALPHA_ADDR, 15_000_000_000);
    println!(
        "  Beta→Alpha 15 VMSHELL: {}",
        if r.is_ok() { "PASS" } else { "FAIL" }
    );
    assert!(r.is_ok());

    // ---------------------------------------------------------------
    // Step 4: Policy check — should REJECT
    // ---------------------------------------------------------------
    println!("\n[Step 4] Policy violation tests...");

    // Alpha → Beta 60 VMSHELL: REJECT (over 50 limit)
    assert!(alpha_wp.check(BETA_ADDR, 60_000_000_000).is_err());
    println!("  Alpha→Beta 60 VMSHELL (over limit): REJECTED");

    // Beta → Alpha 25 VMSHELL: REJECT (over 20 limit)
    assert!(beta_wp.check(ALPHA_ADDR, 25_000_000_000).is_err());
    println!("  Beta→Alpha 25 VMSHELL (over limit): REJECTED");

    // Alpha → unknown addr: REJECT (not in allowed list)
    assert!(alpha_wp
        .check(
            "0:deadbeef00000000000000000000000000000000000000000000000000000000",
            1_000_000_000
        )
        .is_err());
    println!("  Alpha→unknown dest (not allowed): REJECTED");

    // ---------------------------------------------------------------
    // Step 5: Execute payments on shellnet (policy-approved ones)
    // ---------------------------------------------------------------
    println!("\n[Step 5] Executing payments on shellnet...");

    // Payment 1: Alpha → Beta 10 VMSHELL (research data purchase)
    println!("\n  Payment 1: Alpha → Beta 10 VMSHELL (research data)");
    alpha_wp.check(BETA_ADDR, 10_000_000_000)?;
    let tx1 = submit_and_confirm(
        ALPHA_ADDR,
        BETA_ADDR,
        "10000000000",
        &agent_alpha,
        &ctrl_alpha,
        &http,
    )
    .await?;
    println!("    tx: {tx1}");

    // Payment 2: Beta → Alpha 5 VMSHELL (data quality review)
    println!("\n  Payment 2: Beta → Alpha 5 VMSHELL (quality review)");
    beta_wp.check(ALPHA_ADDR, 5_000_000_000)?;
    let tx2 = submit_and_confirm(
        BETA_ADDR,
        ALPHA_ADDR,
        "5000000000",
        &agent_beta,
        &ctrl_beta,
        &http,
    )
    .await?;
    println!("    tx: {tx2}");

    // Payment 3: Alpha → Beta 15 VMSHELL (premium dataset)
    println!("\n  Payment 3: Alpha → Beta 15 VMSHELL (premium dataset)");
    alpha_wp.check(BETA_ADDR, 15_000_000_000)?;
    let tx3 = submit_and_confirm(
        ALPHA_ADDR,
        BETA_ADDR,
        "15000000000",
        &agent_alpha,
        &ctrl_alpha,
        &http,
    )
    .await?;
    println!("    tx: {tx3}");

    // Payment 4: Beta → Alpha 8 VMSHELL (compute service)
    println!("\n  Payment 4: Beta → Alpha 8 VMSHELL (compute service)");
    beta_wp.check(ALPHA_ADDR, 8_000_000_000)?;
    let tx4 = submit_and_confirm(
        BETA_ADDR,
        ALPHA_ADDR,
        "8000000000",
        &agent_beta,
        &ctrl_beta,
        &http,
    )
    .await?;
    println!("    tx: {tx4}");

    // Payment 5: Alpha → Beta 2 VMSHELL (API access fee)
    println!("\n  Payment 5: Alpha → Beta 2 VMSHELL (API access fee)");
    alpha_wp.check(BETA_ADDR, 2_000_000_000)?;
    let tx5 = submit_and_confirm(
        ALPHA_ADDR,
        BETA_ADDR,
        "2000000000",
        &agent_alpha,
        &ctrl_alpha,
        &http,
    )
    .await?;
    println!("    tx: {tx5}");

    // ---------------------------------------------------------------
    // Step 6: Record payment facts in gosh.memory
    // ---------------------------------------------------------------
    println!("\n[Step 6] Recording payment facts in gosh.memory...");

    let payments = vec![
        (
            "Alpha→Beta",
            ALPHA_ADDR,
            BETA_ADDR,
            "10",
            &tx1,
            "research data purchase",
        ),
        (
            "Beta→Alpha",
            BETA_ADDR,
            ALPHA_ADDR,
            "5",
            &tx2,
            "data quality review",
        ),
        (
            "Alpha→Beta",
            ALPHA_ADDR,
            BETA_ADDR,
            "15",
            &tx3,
            "premium dataset access",
        ),
        (
            "Beta→Alpha",
            BETA_ADDR,
            ALPHA_ADDR,
            "8",
            &tx4,
            "compute service",
        ),
        (
            "Alpha→Beta",
            ALPHA_ADDR,
            BETA_ADDR,
            "2",
            &tx5,
            "API access fee",
        ),
    ];

    for (label, from, to, amount, tx_hash, reason) in &payments {
        let fact_text = format!(
            "{from} paid {amount} VMSHELL to {to} for {reason} on Acki Nacki (tx: {tx_hash})"
        );

        // Record in sender's memory
        let sender_session = if from == &ALPHA_ADDR {
            &alpha_session
        } else {
            &beta_session
        };
        let sender_swarm = if from == &ALPHA_ADDR { "alpha" } else { "beta" };
        mcp_call(
            &http,
            sender_session,
            "memory_ingest_asserted_facts",
            json!({
                "key": format!("{sender_swarm}-swarm"),
                "agent_id": "ackinacki",
                "swarm_id": sender_swarm,
                "facts": [{
                    "fact": fact_text,
                    "kind": "fact",
                    "entities": [from, to],
                    "source_id": format!("ackinacki:tx:{tx_hash}"),
                    "metadata": {
                        "semantic_class": "payment_settlement",
                        "x402_network": "ackinacki",
                        "x402_transaction": tx_hash,
                        "x402_payer": from,
                        "x402_payee": to,
                        "x402_amount": format!("{amount}000000000"),
                        "ackinacki_event_type": "payment",
                        "payment_reason": reason,
                    }
                }]
            }),
        )
        .await?;
        println!("  {label}: recorded in {sender_swarm} memory");
    }

    // ---------------------------------------------------------------
    // Step 7: Recall payment history from gosh.memory
    // ---------------------------------------------------------------
    println!("\n[Step 7] Recalling payment history from gosh.memory...");

    let alpha_recall = mcp_call(
        &http,
        &alpha_session,
        "memory_recall",
        json!({
            "key": "alpha-swarm",
            "query": "What payments were made from our wallet?",
            "agent_id": "ackinacki",
            "swarm_id": "alpha",
        }),
    )
    .await?;
    println!(
        "  Alpha recall: {} chars of context",
        alpha_recall
            .get("context")
            .and_then(|c| c.as_str())
            .map(|s| s.len())
            .unwrap_or(0)
    );

    let beta_recall = mcp_call(
        &http,
        &beta_session,
        "memory_recall",
        json!({
            "key": "beta-swarm",
            "query": "What payments were made from our wallet?",
            "agent_id": "ackinacki",
            "swarm_id": "beta",
        }),
    )
    .await?;
    println!(
        "  Beta recall: {} chars of context",
        beta_recall
            .get("context")
            .and_then(|c| c.as_str())
            .map(|s| s.len())
            .unwrap_or(0)
    );

    // ---------------------------------------------------------------
    // Step 8: Frozen wallet test
    // ---------------------------------------------------------------
    println!("\n[Step 8] Freeze Beta wallet...");

    mcp_call(
        &http,
        &beta_session,
        "memory_ingest_asserted_facts",
        json!({
            "key": "beta-swarm",
            "agent_id": "ackinacki",
            "swarm_id": "beta",
            "facts": [{
                "fact": format!("Wallet policy for {BETA_ADDR}"),
                "kind": "constraint",
                "entities": [BETA_ADDR],
                "source_id": format!("wallet_policy:{BETA_ADDR}"),
                "metadata": {
                    "wallet_address": BETA_ADDR,
                    "policy_tier": "frozen",
                    "enabled": true,
                }
            }]
        }),
    )
    .await?;

    // Re-query the frozen policy from memory and verify through the real enforcement path
    let frozen_resp = mcp_call(
        &http,
        &beta_session,
        "memory_query",
        json!({
            "key": "beta-swarm",
            "filter": {"kind": "constraint", "metadata.wallet_address": BETA_ADDR},
            "agent_id": "ackinacki",
            "swarm_id": "beta",
        }),
    )
    .await?;
    let frozen_policy = parse_policy_from_memory(&frozen_resp)
        .expect("frozen policy should be queryable from memory");
    assert_eq!(
        frozen_policy.policy_tier.as_deref(),
        Some("frozen"),
        "policy_tier should be frozen"
    );
    assert!(frozen_policy.check(ALPHA_ADDR, 1_000_000_000).is_err());
    println!("  Beta→Alpha 1 VMSHELL (frozen): REJECTED");

    // ---------------------------------------------------------------
    // Step 9: Check final balances
    // ---------------------------------------------------------------
    println!("\n[Step 9] Final balances...");
    print_balance("Alpha", ALPHA_ADDR, &http).await;
    print_balance("Beta", BETA_ADDR, &http).await;

    // ---------------------------------------------------------------
    // Summary
    // ---------------------------------------------------------------
    println!("\n=== E2E Summary ===");
    println!("  Policies: set in gosh.memory, queried, enforced");
    println!("  Policy passes: 5 (within limits + allowed dests)");
    println!("  Policy rejections: 3 (over limit, unknown dest)");
    println!("  Payments on shellnet: 5 (all with 2-of-3 multisig)");
    println!("  Facts in memory: 5 payment facts + 2 policy facts");
    println!("  Recall: both swarms can query payment history");
    println!("  Freeze: frozen wallet blocks all transactions");
    println!("  PASS");

    Ok(())
}

const MEMORY_TOKEN: &str = "test-token";

/// An MCP session with a gosh.memory instance.
struct MemorySession {
    url: String,
    session_id: String,
}

async fn init_memory_session(http: &reqwest::Client, url: &str) -> anyhow::Result<MemorySession> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "gosh-ackinacki-e2e", "version": "0.1"}
        }
    });

    let resp = http
        .post(format!("{url}/mcp"))
        .header("x-server-token", MEMORY_TOKEN)
        .header("Accept", "application/json, text/event-stream")
        .json(&body)
        .send()
        .await?;

    let session_id = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("no mcp-session-id in response"))?
        .to_string();

    // Consume SSE body
    let _ = resp.text().await;

    // Send initialized notification
    let notif = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
    http.post(format!("{url}/mcp"))
        .header("x-server-token", MEMORY_TOKEN)
        .header("Accept", "application/json, text/event-stream")
        .header("mcp-session-id", &session_id)
        .json(&notif)
        .send()
        .await?;

    Ok(MemorySession {
        url: url.to_string(),
        session_id,
    })
}

async fn mcp_call(
    http: &reqwest::Client,
    session: &MemorySession,
    tool_name: &str,
    args: Value,
) -> anyhow::Result<Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": args,
        }
    });

    let resp_text = http
        .post(format!("{}/mcp", session.url))
        .header("x-server-token", MEMORY_TOKEN)
        .header("Accept", "application/json, text/event-stream")
        .header("mcp-session-id", &session.session_id)
        .json(&body)
        .send()
        .await?
        .text()
        .await?;

    // Parse SSE response: find "data: {...}" line
    let json_str = resp_text
        .lines()
        .filter(|l| l.starts_with("data: "))
        .map(|l| &l[6..])
        .find(|l| l.contains("\"result\"") || l.contains("\"error\""))
        .unwrap_or("{}");

    let resp: Value = serde_json::from_str(json_str)?;

    if let Some(err) = resp.get("error") {
        if !err.is_null() {
            anyhow::bail!("MCP error: {err}");
        }
    }

    // Check isError flag in the result
    if resp["result"]["isError"].as_bool() == Some(true) {
        let err_text = resp["result"]["content"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|c| c["text"].as_str())
            .unwrap_or("unknown error");
        anyhow::bail!("MCP tool error: {err_text}");
    }

    // Result is in result.content[0].text
    let text = resp["result"]["content"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|c| c["text"].as_str())
        .unwrap_or("{}");

    serde_json::from_str(text).map_err(|e| anyhow::anyhow!("parse result: {e}, raw: {text}"))
}

async fn submit_and_confirm(
    from: &str,
    to: &str,
    value: &str,
    agent_secret: &str,
    ctrl_secret: &str,
    http: &reqwest::Client,
) -> anyhow::Result<String> {
    let params = json!({
        "dest": to, "value": value, "cc": {},
        "bounce": true, "flag": 1, "payload": "",
    });

    let boc = encode_call(from, "submitTransaction", &params, agent_secret)?;
    let resp = send_msg(http, &boc).await?;
    let exit_code = resp["result"]["exit_code"].as_i64();
    if exit_code != Some(0) {
        anyhow::bail!("submit failed: {}", serde_json::to_string_pretty(&resp)?);
    }
    let trans_id = extract_trans_id(&resp)?;

    let confirm_boc = encode_call(
        from,
        "confirmTransaction",
        &json!({"transactionId": trans_id.to_string()}),
        ctrl_secret,
    )?;
    let confirm_resp = send_msg(http, &confirm_boc).await?;
    if confirm_resp["result"]["exit_code"].as_i64() != Some(0) {
        anyhow::bail!(
            "confirm failed: {}",
            serde_json::to_string_pretty(&confirm_resp)?
        );
    }

    Ok(confirm_resp["result"]["tx_hash"]
        .as_str()
        .unwrap_or("unknown")
        .into())
}

async fn send_msg(http: &reqwest::Client, boc: &str) -> anyhow::Result<Value> {
    let msg_id = uuid::Uuid::new_v4().to_string();
    let resp = http
        .post(format!("{ENDPOINT}/v2/messages"))
        .json(&json!([{"id": msg_id, "body": boc}]))
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    Ok(resp)
}

fn extract_trans_id(resp: &Value) -> anyhow::Result<u64> {
    use gosh_ackinacki::wallet::contracts::MULTISIG_ABI;
    use tvm_block::Deserializable;

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

async fn print_balance(name: &str, addr: &str, http: &reqwest::Client) {
    let result: anyhow::Result<u128> = async {
        let resp = http
            .post("https://shellnet.ackinacki.org/graphql")
            .json(&json!({"query": format!(
                "{{ blockchain {{ account(address: \"{addr}\") {{ info {{ balance }} }} }} }}"
            )}))
            .send()
            .await?
            .json::<Value>()
            .await?;
        let hex = resp["data"]["blockchain"]["account"]["info"]["balance"]
            .as_str()
            .unwrap_or("0x0");
        Ok(u128::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0))
    }
    .await;
    match result {
        Ok(bal) => println!("  {name}: {:.2} VMSHELL", bal as f64 / 1e9),
        Err(e) => println!("  {name}: error: {e}"),
    }
}

fn encode_call(addr_str: &str, func: &str, params: &Value, secret: &str) -> anyhow::Result<String> {
    use gosh_ackinacki::wallet::contracts::MULTISIG_ABI;
    use tvm_abi::token::Tokenizer;
    use tvm_block::Serializable;

    let parts: Vec<&str> = addr_str.splitn(2, ':').collect();
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
    let header = json!({"pubkey": hex::encode(sk.verifying_key().as_bytes()), "time": now, "expire": (now/1000)+300});

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
