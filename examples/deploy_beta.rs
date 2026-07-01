use gosh_ackinacki::wallet::deploy::{prepare_deploy, DeployParams};
use gosh_ackinacki::wallet::query::send_message;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http = reqwest::Client::new();
    let agent_beta = std::env::var("AGENT_BETA_SECRET").expect("set AGENT_BETA_SECRET env var");
    let ctrl_beta = std::env::var("CTRL_BETA_SECRET").expect("set CTRL_BETA_SECRET env var");
    let owner = std::env::var("OWNER_SECRET").expect("set OWNER_SECRET env var");
    let pubkey = |secret: &str| -> String {
        let bytes: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&bytes)
                .verifying_key()
                .as_bytes(),
        )
    };
    let params = DeployParams {
        agent_pubkey: pubkey(&agent_beta),
        controller_pubkey: pubkey(&ctrl_beta),
        owner_pubkey: pubkey(&owner),
        initial_value: 500_000_000,
    };
    let prepared = prepare_deploy(&params, &agent_beta)?;
    println!("Address: {}", prepared.address);
    let resp = send_message(
        &http,
        "https://shellnet.ackinacki.org",
        &prepared.message_boc_base64,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
