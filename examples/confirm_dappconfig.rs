use gosh_ackinacki::wallet::query::send_message;
use gosh_ackinacki::wallet::transact::encode_confirm_transaction;

const WALLET_ADDR: &str = "0:03079cdd1f5c3044fb3f7993becb2f581ffc1e3d128db4afc411e7870af883c3";
const ENDPOINT: &str = "https://shellnet.ackinacki.org";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http = reqwest::Client::new();
    let controller_secret =
        std::env::var("CONTROLLER_SECRET").expect("set CONTROLLER_SECRET env var");
    let parts: Vec<&str> = WALLET_ADDR.splitn(2, ':').collect();
    let wc: i8 = parts[0].parse()?;
    let bytes = hex::decode(parts[1])?;
    let addr = tvm_block::MsgAddressInt::with_standart(
        None,
        wc,
        tvm_types::AccountId::from_raw(bytes, 256),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let trans_id: u64 = 21468162;
    println!("Confirming transId={trans_id} from controller...");
    let boc = encode_confirm_transaction(&addr, trans_id, &controller_secret)?;
    let resp = send_message(&http, ENDPOINT, &boc).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
