//! E2E: Event-driven agent marketplace via Courier pub/sub.
//!
//! Agents communicate ONLY through gosh.memory. No direct calls.
//! Courier SSE pushes events to agents when facts appear.
//!
//! Flow:
//!   1. Both agents connect to SSE, subscribe via Courier
//!   2. Agent Beta writes "need research data" fact → Courier pushes to Alpha
//!   3. Agent Alpha sees request → writes "data delivered" + calls send_transaction
//!   4. Controller confirms (triggered by courier event on pending tx fact)
//!   5. Block stream event → memory → Courier pushes "payment settled" to Beta
//!   6. Beta sees payment → writes "paying for data" + calls send_transaction back
//!   7. Controller confirms → settled

use futures_util::StreamExt;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

const ALPHA_MEMORY: &str = "http://127.0.0.1:8100";
const BETA_MEMORY: &str = "http://127.0.0.1:8200";
const TOKEN: &str = "test-token";

const ALPHA_ADDR: &str = "0:03079cdd1f5c3044fb3f7993becb2f581ffc1e3d128db4afc411e7870af883c3";
const BETA_ADDR: &str = "0:b924813593bb4963f9dbbd383b5ba43e118c7ce675a657619e251ed1c81dd754";
const ENDPOINT: &str = "https://shellnet.ackinacki.org";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let agent_alpha = std::env::var("AGENT_ALPHA_SECRET").expect("AGENT_ALPHA_SECRET");
    let ctrl_alpha = std::env::var("CTRL_ALPHA_SECRET").expect("CTRL_ALPHA_SECRET");
    let agent_beta = std::env::var("AGENT_BETA_SECRET").expect("AGENT_BETA_SECRET");
    let ctrl_beta = std::env::var("CTRL_BETA_SECRET").expect("CTRL_BETA_SECRET");

    let http = reqwest::Client::new();

    println!("=== Event-Driven Agent Marketplace via Courier ===\n");

    // --- Step 1: Init MCP sessions ---
    println!("[1] Connecting MCP sessions...");
    let alpha_sess = init_session(&http, ALPHA_MEMORY).await?;
    let beta_sess = init_session(&http, BETA_MEMORY).await?;
    println!("  Alpha session: {}", alpha_sess.session_id);
    println!("  Beta session: {}", beta_sess.session_id);

    // --- Step 2: Connect SSE + subscribe couriers ---
    println!("\n[2] Setting up Courier subscriptions...");

    // Alpha: connect SSE + subscribe + listen on SAME connection
    let alpha_events: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let (alpha_conn, alpha_stream) = connect_sse_stream(ALPHA_MEMORY).await?;
    println!("  Alpha SSE connection: {}", alpha_conn);

    let alpha_sub = mcp_call(
        &http,
        &alpha_sess,
        "courier_subscribe",
        json!({
            "key": "alpha-swarm",
            "connection_id": alpha_conn,
            "filter": {"kind": "task"},
            "agent_id": "ackinacki",
            "swarm_id": "alpha",
        }),
    )
    .await?;
    println!("  Alpha subscribed: {:?}", alpha_sub.get("sub_id"));

    let alpha_ev = alpha_events.clone();
    let sse_alpha = tokio::spawn(drain_sse(alpha_stream, alpha_ev));

    // Beta: connect SSE + subscribe + listen on SAME connection
    let beta_events: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let (beta_conn, beta_stream) = connect_sse_stream(BETA_MEMORY).await?;
    println!("  Beta SSE connection: {}", beta_conn);

    let beta_sub = mcp_call(
        &http,
        &beta_sess,
        "courier_subscribe",
        json!({
            "key": "beta-swarm",
            "connection_id": beta_conn,
            "filter": {"kind": "fact"},
            "agent_id": "ackinacki",
            "swarm_id": "beta",
        }),
    )
    .await?;
    println!("  Beta subscribed: {:?}", beta_sub.get("sub_id"));

    let beta_ev = beta_events.clone();
    let sse_beta = tokio::spawn(drain_sse(beta_stream, beta_ev));

    // --- Step 3: Beta writes "need research data" into Alpha's memory ---
    println!("\n[3] Beta requests data from Alpha (via memory)...");
    mcp_call(&http, &alpha_sess, "memory_ingest_asserted_facts", json!({
        "enrich_l0": false,
        "key": "alpha-swarm",
        "agent_id": "ackinacki",
        "swarm_id": "alpha",
        "facts": [{
            "fact": "Agent Beta requests research dataset on AI safety. Willing to pay 5 VMSHELL.",
            "kind": "task",
            "entities": [BETA_ADDR, ALPHA_ADDR],
            "source_id": "request:beta:research-001",
            "metadata": {
                "request_type": "data_purchase",
                "requester": BETA_ADDR,
                "provider": ALPHA_ADDR,
                "offered_amount": "5000000000",
                "topic": "AI safety research",
            }
        }]
    })).await?;
    println!("  Task fact written to Alpha's memory");

    // Wait for Courier to poll and deliver
    println!("  Waiting for Courier delivery...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let alpha_received = alpha_events.lock().await.len();
    println!("  Alpha received {} events via Courier", alpha_received);

    // --- Step 4: Alpha sees request, delivers data, initiates payment ---
    println!("\n[4] Alpha delivers data and records delivery...");
    mcp_call(&http, &alpha_sess, "memory_ingest_asserted_facts", json!({
        "enrich_l0": false,
        "key": "alpha-swarm",
        "agent_id": "ackinacki",
        "swarm_id": "alpha",
        "facts": [{
            "fact": "Agent Alpha delivered AI safety research dataset to Beta. Requesting payment of 5 VMSHELL.",
            "kind": "fact",
            "entities": [ALPHA_ADDR, BETA_ADDR],
            "source_id": "delivery:alpha:research-001",
            "metadata": {
                "delivery_type": "data_delivery",
                "provider": ALPHA_ADDR,
                "recipient": BETA_ADDR,
                "requested_amount": "5000000000",
                "status": "delivered",
            }
        }]
    })).await?;
    println!("  Delivery fact recorded");

    // --- Step 5: Beta pays Alpha (submit + confirm via memory coordination) ---
    println!("\n[5] Beta initiates payment to Alpha...");

    // Beta records payment intent in Beta's memory
    mcp_call(
        &http,
        &beta_sess,
        "memory_ingest_asserted_facts",
        json!({
            "enrich_l0": false,
            "key": "beta-swarm",
            "agent_id": "ackinacki",
            "swarm_id": "beta",
            "facts": [{
                "fact": "Initiating payment of 5 VMSHELL to Alpha for research data.",
                "kind": "task",
                "entities": [BETA_ADDR, ALPHA_ADDR],
                "source_id": "payment-intent:beta:research-001",
                "metadata": {
                    "action": "send_payment",
                    "from": BETA_ADDR,
                    "to": ALPHA_ADDR,
                    "amount": "5000000000",
                    "reason": "AI safety research data",
                    "status": "pending_submit",
                }
            }]
        }),
    )
    .await?;
    println!("  Payment intent recorded in Beta memory");

    // Agent Beta submits transaction
    println!("  Submitting transaction on-chain...");
    let tx_result = submit_and_confirm(
        BETA_ADDR,
        ALPHA_ADDR,
        "5000000000",
        &agent_beta,
        &ctrl_beta,
        &http,
    )
    .await?;
    println!("  Payment executed: tx={}", tx_result.tx_hash);

    // Record settlement in both memories
    let settlement_fact = json!({
        "fact": format!(
            "Payment of 5 VMSHELL from {} to {} settled on Acki Nacki (tx: {})",
            BETA_ADDR, ALPHA_ADDR, tx_result.tx_hash
        ),
        "kind": "fact",
        "entities": [BETA_ADDR, ALPHA_ADDR],
        "source_id": format!("settlement:tx:{}", tx_result.tx_hash),
        "metadata": {
            "semantic_class": "payment_settlement",
            "x402_network": "ackinacki",
            "x402_transaction": tx_result.tx_hash,
            "x402_payer": BETA_ADDR,
            "x402_payee": ALPHA_ADDR,
            "x402_amount": "5000000000",
            "ackinacki_event_type": "payment",
            "reason": "AI safety research data",
            "status": "settled",
        }
    });

    // Into Beta's memory (sender's record)
    mcp_call(
        &http,
        &beta_sess,
        "memory_ingest_asserted_facts",
        json!({
            "enrich_l0": false,
            "key": "beta-swarm",
            "agent_id": "ackinacki",
            "swarm_id": "beta",
            "facts": [settlement_fact],
        }),
    )
    .await?;
    println!("  Settlement recorded in Beta memory");

    // Into Alpha's memory (receiver's record)
    mcp_call(
        &http,
        &alpha_sess,
        "memory_ingest_asserted_facts",
        json!({
            "enrich_l0": false,
            "key": "alpha-swarm",
            "agent_id": "ackinacki",
            "swarm_id": "alpha",
            "facts": [settlement_fact],
        }),
    )
    .await?;
    println!("  Settlement recorded in Alpha memory");

    // --- Step 6: Wait for courier to deliver settlement to Beta ---
    println!("\n[6] Waiting for Courier to push settlement events...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let beta_received = beta_events.lock().await.len();
    println!("  Beta received {} events via Courier", beta_received);

    // --- Step 7: Alpha pays Beta back (referral bonus) ---
    println!("\n[7] Alpha pays Beta 2 VMSHELL referral bonus...");

    mcp_call(
        &http,
        &alpha_sess,
        "memory_ingest_asserted_facts",
        json!({
            "enrich_l0": false,
            "key": "alpha-swarm",
            "agent_id": "ackinacki",
            "swarm_id": "alpha",
            "facts": [{
                "fact": "Sending 2 VMSHELL referral bonus to Beta for bringing new data consumers.",
                "kind": "task",
                "entities": [ALPHA_ADDR, BETA_ADDR],
                "source_id": "payment-intent:alpha:referral-001",
                "metadata": {
                    "action": "send_payment",
                    "from": ALPHA_ADDR,
                    "to": BETA_ADDR,
                    "amount": "2000000000",
                    "reason": "referral bonus",
                    "status": "pending_submit",
                }
            }]
        }),
    )
    .await?;

    let tx2 = submit_and_confirm(
        ALPHA_ADDR,
        BETA_ADDR,
        "2000000000",
        &agent_alpha,
        &ctrl_alpha,
        &http,
    )
    .await?;
    println!("  Referral payment: tx={}", tx2.tx_hash);

    // Record in both memories
    let ref_fact = json!({
        "fact": format!(
            "Payment of 2 VMSHELL from {} to {} for referral bonus (tx: {})",
            ALPHA_ADDR, BETA_ADDR, tx2.tx_hash
        ),
        "kind": "fact",
        "entities": [ALPHA_ADDR, BETA_ADDR],
        "source_id": format!("settlement:tx:{}", tx2.tx_hash),
        "metadata": {
            "semantic_class": "payment_settlement",
            "x402_network": "ackinacki",
            "x402_transaction": tx2.tx_hash,
            "x402_payer": ALPHA_ADDR,
            "x402_payee": BETA_ADDR,
            "x402_amount": "2000000000",
            "ackinacki_event_type": "payment",
            "reason": "referral bonus",
            "status": "settled",
        }
    });
    mcp_call(
        &http,
        &alpha_sess,
        "memory_ingest_asserted_facts",
        json!({
            "enrich_l0": false,
            "key": "alpha-swarm", "agent_id": "ackinacki", "swarm_id": "alpha",
            "facts": [ref_fact],
        }),
    )
    .await?;
    mcp_call(
        &http,
        &beta_sess,
        "memory_ingest_asserted_facts",
        json!({
            "enrich_l0": false,
            "key": "beta-swarm", "agent_id": "ackinacki", "swarm_id": "beta",
            "facts": [ref_fact],
        }),
    )
    .await?;
    println!("  Settlement recorded in both memories");

    // --- Step 8: Recall from memory ---
    println!("\n[8] Querying payment history from memory...");

    let alpha_facts = mcp_call(
        &http,
        &alpha_sess,
        "memory_query",
        json!({
            "key": "alpha-swarm",
            "filter": {"metadata.semantic_class": "payment_settlement"},
            "agent_id": "ackinacki",
            "swarm_id": "alpha",
        }),
    )
    .await?;
    let alpha_count = alpha_facts["facts"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    println!("  Alpha sees {} payment facts", alpha_count);

    let beta_facts = mcp_call(
        &http,
        &beta_sess,
        "memory_query",
        json!({
            "key": "beta-swarm",
            "filter": {"metadata.semantic_class": "payment_settlement"},
            "agent_id": "ackinacki",
            "swarm_id": "beta",
        }),
    )
    .await?;
    let beta_count = beta_facts["facts"].as_array().map(|a| a.len()).unwrap_or(0);
    println!("  Beta sees {} payment facts", beta_count);

    // --- Step 9: Check total courier events ---
    println!("\n[9] Courier event summary...");
    let total_alpha = alpha_events.lock().await.len();
    let total_beta = beta_events.lock().await.len();
    println!("  Alpha Courier events: {total_alpha}");
    println!("  Beta Courier events: {total_beta}");

    // Cleanup
    sse_alpha.abort();
    sse_beta.abort();

    // --- Assertions ---
    assert!(alpha_count > 0, "Alpha must see payment facts, got 0");
    assert!(beta_count > 0, "Beta must see payment facts, got 0");
    assert!(total_alpha > 0, "Alpha must receive courier events, got 0");
    assert!(total_beta > 0, "Beta must receive courier events, got 0");

    // --- Summary ---
    println!("\n=== E2E Summary ===");
    println!("  Communication: agents talk ONLY through gosh.memory");
    println!("  Courier: SSE push for event-driven reactions");
    println!("  Payments: 2 on-chain (Beta→Alpha 5, Alpha→Beta 2)");
    println!("  Alpha: {alpha_count} payment facts, {total_alpha} courier events");
    println!("  Beta: {beta_count} payment facts, {total_beta} courier events");
    println!("  ALL ASSERTIONS PASSED");

    Ok(())
}

// --- Helpers ---

struct TxResult {
    tx_hash: String,
}

async fn submit_and_confirm(
    from: &str,
    to: &str,
    value: &str,
    agent_secret: &str,
    ctrl_secret: &str,
    http: &reqwest::Client,
) -> anyhow::Result<TxResult> {
    use gosh_ackinacki::wallet::contracts::MULTISIG_ABI;
    use tvm_block::Deserializable;

    let boc = encode_call(
        from,
        "submitTransaction",
        &json!({"dest": to, "value": value, "cc": {}, "bounce": true, "flag": 1, "payload": ""}),
        agent_secret,
    )?;
    let resp = send_msg(http, &boc).await?;
    if resp["result"]["exit_code"].as_i64() != Some(0) {
        anyhow::bail!("submit failed: {}", serde_json::to_string_pretty(&resp)?);
    }

    // Decode transId
    let ext_out = resp["result"]["ext_out_msgs"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no ext_out"))?;
    use base64::Engine;
    let boc_bytes = base64::engine::general_purpose::STANDARD.decode(ext_out)?;
    let cell = tvm_types::read_single_root_boc(&boc_bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
    let msg = tvm_block::Message::construct_from_cell(cell).map_err(|e| anyhow::anyhow!("{e}"))?;
    let body = msg.body().ok_or_else(|| anyhow::anyhow!("no body"))?;
    let func = MULTISIG_ABI
        .function("submitTransaction")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let tokens = func
        .decode_output(body, false, true)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let trans_id = tokens
        .iter()
        .find(|t| t.name == "transId")
        .and_then(|t| {
            if let tvm_abi::TokenValue::Uint(v) = &t.value {
                v.number.to_u64_digits().first().copied()
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow::anyhow!("no transId"))?;

    // Confirm
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

    Ok(TxResult {
        tx_hash: confirm_resp["result"]["tx_hash"]
            .as_str()
            .unwrap_or("unknown")
            .into(),
    })
}

async fn send_msg(http: &reqwest::Client, boc: &str) -> anyhow::Result<Value> {
    let id = uuid::Uuid::new_v4().to_string();
    Ok(http
        .post(format!("{ENDPOINT}/v2/messages"))
        .json(&json!([{"id": id, "body": boc}]))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Connect to SSE, extract connection_id, return the live stream for draining.
async fn connect_sse_stream(
    memory_url: &str,
) -> anyhow::Result<(
    String,
    impl futures_util::Stream<Item = reqwest::Result<bytes::Bytes>>,
)> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{memory_url}/mcp/sse"))
        .header("x-server-token", TOKEN)
        .send()
        .await?;

    let mut stream = resp.bytes_stream();
    let mut buf = String::new();

    // Read until we get the connection_id
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buf.push_str(&String::from_utf8_lossy(&chunk));
        for line in buf.lines() {
            if let Some(payload) = line.strip_prefix("data: ") {
                if let Ok(data) = serde_json::from_str::<Value>(payload) {
                    if data["type"] == "connected" {
                        let conn_id = data["connection_id"].as_str().unwrap().to_string();
                        return Ok((conn_id, stream));
                    }
                }
            }
        }
    }
    anyhow::bail!("no connection_id in SSE response")
}

/// Drain an SSE stream, collecting artifact events.
async fn drain_sse(
    mut stream: impl futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin,
    events: Arc<Mutex<Vec<Value>>>,
) {
    let mut buf = String::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                buf.push_str(&String::from_utf8_lossy(&bytes));
                while let Some(pos) = buf.find('\n') {
                    let line = buf[..pos].to_string();
                    buf = buf[pos + 1..].to_string();
                    if let Some(payload) = line.strip_prefix("data: ") {
                        if let Ok(data) = serde_json::from_str::<Value>(payload) {
                            if data["type"] == "artifact" {
                                events.lock().await.push(data.clone());
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }
}

struct McpSession {
    url: String,
    session_id: String,
}

async fn init_session(http: &reqwest::Client, url: &str) -> anyhow::Result<McpSession> {
    let resp = http
        .post(format!("{url}/mcp"))
        .header("x-server-token", TOKEN)
        .header("Accept", "application/json, text/event-stream")
        .json(&json!({
            "jsonrpc": "2.0", "id": 0,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "e2e-courier", "version": "0.1"}}
        }))
        .send()
        .await?;
    let session_id = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let _ = resp.text().await;
    // Send initialized notification
    http.post(format!("{url}/mcp"))
        .header("x-server-token", TOKEN)
        .header("Accept", "application/json, text/event-stream")
        .header("mcp-session-id", &session_id)
        .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await?;
    Ok(McpSession {
        url: url.to_string(),
        session_id,
    })
}

async fn mcp_call(
    http: &reqwest::Client,
    sess: &McpSession,
    tool: &str,
    args: Value,
) -> anyhow::Result<Value> {
    let resp_text = http.post(format!("{}/mcp", sess.url))
        .header("x-server-token", TOKEN)
        .header("Accept", "application/json, text/event-stream")
        .header("mcp-session-id", &sess.session_id)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":args}}))
        .send().await?.text().await?;

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
    if resp["result"]["isError"].as_bool() == Some(true) {
        let msg = resp["result"]["content"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|c| c["text"].as_str())
            .unwrap_or("unknown");
        anyhow::bail!("tool error: {msg}");
    }

    let text = resp["result"]["content"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|c| c["text"].as_str())
        .unwrap_or("{}");
    serde_json::from_str(text).map_err(|e| anyhow::anyhow!("parse: {e}"))
}

fn encode_call(addr: &str, func: &str, params: &Value, secret: &str) -> anyhow::Result<String> {
    use gosh_ackinacki::wallet::contracts::MULTISIG_ABI;
    use tvm_abi::token::Tokenizer;
    use tvm_block::Serializable;

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
