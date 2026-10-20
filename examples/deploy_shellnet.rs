use gosh_ackinacki::wallet::deploy::{prepare_deploy, DeployParams};
use gosh_ackinacki::wallet::query::send_message;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http = reqwest::Client::new();
    let agent_secret = std::env::var("AGENT_SECRET").expect("set AGENT_SECRET env var");
    let controller_secret =
        std::env::var("CONTROLLER_SECRET").expect("set CONTROLLER_SECRET env var");
    let owner_secret = std::env::var("OWNER_SECRET").expect("set OWNER_SECRET env var");

    let pubkey = |secret: &str| -> String {
        let bytes: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        hex::encode(key.verifying_key().as_bytes())
    };

    let params = DeployParams {
        agent_pubkey: pubkey(&agent_secret),
        controller_pubkey: pubkey(&controller_secret),
        owner_pubkey: pubkey(&owner_secret),
        initial_value: 1_000_000_000,
    };

    println!("Preparing deploy message...");
    let prepared = prepare_deploy(&params, &agent_secret)?;
    println!("Address: {}", prepared.address);
    println!("BOC length: {} bytes", prepared.message_boc_base64.len());

    println!("Sending to shellnet...");
    let resp = send_message(
        &http,
        "https://shellnet.ackinacki.org", // public BM endpoint
        &prepared.message_boc_base64,
    )
    .await?;
    println!("Response: {}", serde_json::to_string_pretty(&resp)?);

    Ok(())
}
