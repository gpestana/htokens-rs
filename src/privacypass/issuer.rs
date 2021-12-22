/// Implements the issuer logic for humanity tokens as per the Privacy Pass protocol; 

use crate::privacypass::errors::*;
use crate::privacypass::models::*;

use challenge_bypass_ristretto::voprf::TokenPreimage;
use hmac::Hmac;
use rand::rngs::OsRng;
use sha2::Sha512;

use challenge_bypass_ristretto::voprf::{ BatchDLEQProof, SignedToken, SigningKey };

type HmacSha512 = Hmac<Sha512>;

/// The Issuer issues new humanity tokens by signing blinded tokens from cliens wrapped in a
/// `SigningRequest`
pub struct Issuer {
    signing_key: SigningKey,
}

impl Issuer {
    /// Returns a new initialized Issuer. An Issuer keeps an asymmetric public/secret key pair used
    /// to signs tokens and verify signature. The `SigningKey` is provided when initializing the
    /// Issuer
    pub fn new(signing_key_bytes: &[u8]) -> Self {
        let signing_key = SigningKey::from_bytes(signing_key_bytes).unwrap();
        Issuer { signing_key }
    }

    /// Parses a SigningRequest, signs the incoming tokens and generates a batch DLEQ proof that
    /// claims the validity of the signature based on the Issuer's `SigningKey`
    pub fn sign_tokens(&self, req: SigningRequest) -> Result<SigningResponse, ProtocolError> {
        let mut rng = OsRng;

        let public_key = self.signing_key.public_key;

        let signed_tokens: Vec<SignedToken> = req
            .blinded_tokens
            .iter()
            .filter_map(|t| self.signing_key.sign(t).ok())
            .collect();

        let batch_proof = match BatchDLEQProof::new::<Sha512, OsRng>(
            &mut rng,
            &req.blinded_tokens,
            &signed_tokens,
            &self.signing_key,
        ) {
            Ok(batch) => batch,
            Err(e) => return Err(ProtocolError::new(&e.to_string())),
        };

        Ok(SigningResponse {
            signed_tokens,
            public_key: Some(public_key),
            batch_proof: Some(batch_proof),
            error: "".to_string(),
        })
    }

    /// Processes a RedeemRequest and verifies the validity of the payload; Returns a
    /// RedeemResponse ready to send on the wire and a vector with the token preimages that have
    /// been redeemed by the request for posterior processing and double spending accounting
    pub fn process_redeem_tokens(
        &mut self,
        req: &RedeemRequest,
    ) -> (RedeemResponse, Vec<TokenPreimage>) {
        let mut n_tokens_redeemed: usize = 0;
        let mut redeemed_preimages: Vec<TokenPreimage> = vec![];

        for (preimage, client_sig) in req.preimages.iter().zip(req.verification_signatures.iter()) {
            let unblinded_token = self.signing_key.rederive_unblinded_token(preimage);
            let verification_key = unblinded_token.derive_verification_key::<Sha512>();
            let sig = verification_key.sign::<HmacSha512>(&req.payload);

            // fail
            if *client_sig != sig {
                let ok = false;
                let response = RedeemResponse {
                    ok,
                    n_tokens_redeemed,
                };

                return (response, redeemed_preimages);
            }
            n_tokens_redeemed += 1;
            redeemed_preimages.push(*preimage);
        }

        let ok = true;
        let response = RedeemResponse {
            ok,
            n_tokens_redeemed,
        };

        (response, redeemed_preimages)
    }
}
