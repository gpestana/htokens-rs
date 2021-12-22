use humanity_tokens::privacypass::wallet::*;
use humanity_tokens::privacypass::models::{SigningRequest, SigningResponse, RedeemRequest, 
    RedeemResponse};

fn main() {
    e2e_ok();
}

fn e2e_ok() {
    // init a privacy pass wallet
    let mut pp_wallet = Wallet::new();

    // generate 10 blinded privacy pass tokens
    let (raw_tokens, blinded_tokens) = Wallet::generate_blinded_tokens(10);

    // serialize signing request to send on the wire
    let http_payload = serde_json::to_string(
        &SigningRequest{ 
            blinded_tokens: blinded_tokens.clone()
        }
    ).unwrap();

    let http_cli = reqwest::blocking::Client::new();
    let res = http_cli
        .put("http://127.0.0.1:3000/v1/issue")
        .body(http_payload)
        .send()
        .unwrap();

    // deserialize response as a SigningResponse type
    let signing_response: SigningResponse = res.json().unwrap();

    // process signing tokens; If batch proof provided by issuer does not match, fails
    let _signed_tokens = pp_wallet.process_signed_tokens(
        &signing_response.signed_tokens,
        signing_response.batch_proof,
        signing_response.public_key.unwrap(),
        &raw_tokens,
        &blinded_tokens,
    ).unwrap();

    // Redemption OK

    // pops a signed and unblided tokens to redeem
    let tokens = pp_wallet.get_tokens(1).unwrap();

    let payload = "test".to_string();
    let (preimages, verification_signatures) = Wallet::prepare_redemption(&tokens, payload.clone());

    // serialize redempton request to send on the wire
    let http_payload = serde_json::to_string(
        &RedeemRequest{
            preimages,
            verification_signatures,
            payload: payload.as_bytes().to_vec(),
        }
    ).unwrap();

    let res = http_cli
        .put("http://127.0.0.1:3000/v1/redeem")
        .body(http_payload)
        .send()
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::OK);

    let redeem_response: RedeemResponse = res.json().unwrap();
    println!("{:?}", redeem_response);

    // Redemption failure -- double spending same token

    let res = http_cli
        .put("http://127.0.0.1:3000/v1/redeem")
        .body(payload)
        .send()
        .unwrap();

    assert_ne!(res.status(), reqwest::StatusCode::OK);

    let redeem_response: RedeemResponse = res.json().unwrap();

    println!("{:?}", redeem_response);
}
