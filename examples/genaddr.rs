use gosh_ackinacki::wallet::deploy::{prepare_deploy, DeployParams};

fn main() {
    let agent_secret = std::env::var("AGENT_SECRET").expect("set AGENT_SECRET env var");
    let controller_secret =
        std::env::var("CONTROLLER_SECRET").expect("set CONTROLLER_SECRET env var");
    let owner_secret = std::env::var("OWNER_SECRET").expect("set OWNER_SECRET env var");
    let secrets = [
        ("agent", agent_secret.as_str()),
        ("controller", controller_secret.as_str()),
        ("owner", owner_secret.as_str()),
    ];

    let mut pubkeys = Vec::new();
    for (role, secret) in &secrets {
        let bytes: [u8; 32] = hex::decode(secret).unwrap().try_into().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let pubkey = hex::encode(key.verifying_key().as_bytes());
        println!("{role} pubkey: {pubkey}");
        pubkeys.push(pubkey);
    }

    let params = DeployParams {
        agent_pubkey: pubkeys[0].clone(),
        controller_pubkey: pubkeys[1].clone(),
        owner_pubkey: pubkeys[2].clone(),
        initial_value: 1_000_000_000,
    };

    let deploy = prepare_deploy(&params, secrets[0].1).unwrap();
    println!("\nWALLET ADDRESS: {}", deploy.address);
    println!("\nFund this address with SHELL, then deploy.");
}
