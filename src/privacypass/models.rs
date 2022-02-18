use actix_web::{HttpResponse, Responder};
use actix_http::body::BoxBody;
use std::option::Option;

use challenge_bypass_ristretto::voprf::{
    BatchDLEQProof, BlindedToken, PublicKey, SignedToken, TokenPreimage, VerificationSignature,
};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SigningRequest {
    pub blinded_tokens: Vec<BlindedToken>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigningResponse {
    pub signed_tokens: Vec<SignedToken>,
    pub public_key: Option<PublicKey>,
    pub batch_proof: Option<BatchDLEQProof>,
    pub error: String,
}

impl Responder for SigningResponse {
    type Body = BoxBody;

    fn respond_to(self, _req: &actix_web::HttpRequest) -> HttpResponse {
        let body = serde_json::to_string(&self).unwrap();

        match self.error.as_str() {
            "Request Malformed" => return HttpResponse::BadRequest().finish(),
            &_ => (),
        }

        HttpResponse::Ok()
            .content_type("application/json")
            .body(body)
    }
}

impl SigningResponse {
    pub fn with_error(error: String) -> Self {
        let signed_tokens = vec![];

        SigningResponse {
            signed_tokens,
            public_key: None,
            batch_proof: None,
            error,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RedeemRequest {
    pub preimages: Vec<TokenPreimage>,
    pub verification_signatures: Vec<VerificationSignature>,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RedeemResponse {
    pub ok: bool,
    pub n_tokens_redeemed: usize,
}

impl Responder for RedeemResponse {
    type Body = BoxBody;

    fn respond_to(self, _req: &actix_web::HttpRequest) -> HttpResponse {
        let body = serde_json::to_string(&self).unwrap();

        match self.ok {
            true => HttpResponse::Ok().body(body),
            false => HttpResponse::Unauthorized().body(body),
        }
    }
}

impl RedeemResponse {
    pub fn with_error(_error: &'static str) -> Self {
        RedeemResponse {
            ok: false,
            n_tokens_redeemed: 0,
        }
    }
}
