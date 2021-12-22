/// Wallet implementation for privacy-pass based humanity tokens

use crate::privacypass::errors::*;

use challenge_bypass_ristretto::voprf::{
    BatchDLEQProof, SignedToken, TokenPreimage, VerificationSignature, BlindedToken, Token, 
    UnblindedToken, PublicKey};

use hmac::Hmac;
use rand::rngs::OsRng;
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

pub struct Wallet {
    // TODO: wrap `tokens` into `privacypass:HToken{}`
    tokens: Vec<UnblindedToken>,
}

impl Wallet {

    pub fn new() -> Self {
        let tokens = vec![];

        Wallet { tokens }
    }

    pub fn generate_blinded_tokens(n: usize) -> (Vec<Token>, Vec<BlindedToken>) {
        let mut rng = OsRng;

        let mut raw_tokens: Vec<Token> = vec![];
        let mut blinded_tokens: Vec<BlindedToken> = vec![];

        for _ in 0..n {
            let token = Token::random::<Sha512, OsRng>(&mut rng);
            let blinded_token = token.blind();
            
            raw_tokens.push(token);
            blinded_tokens.push(blinded_token);
        }

        (raw_tokens, blinded_tokens)
    }

   pub fn process_signed_tokens(
        &mut self,
        signed_tokens: &[SignedToken],
        batch_proof: Option<BatchDLEQProof>,
        issuer_pubkey: PublicKey,
        raw_tokens: &[Token],
        blinded_tokens: &[BlindedToken],
    ) -> Result<(), ProtocolError> {
        let batch_proof = match batch_proof {
            Some(batch) => batch,
            None => {
                return Err(ProtocolError::new(
                    "Unexpected error: batch proof not provided",
                ))
            }
        };

        let mut unblinded_tokens = match batch_proof.verify_and_unblind::<Sha512, _>(
            raw_tokens,
            blinded_tokens,
            signed_tokens,
            &issuer_pubkey,
        ) {
            Ok(blinded_tokens) => blinded_tokens,
            Err(err) => return Err(ProtocolError::new(&err.to_string())),
        };

        if unblinded_tokens.len() != raw_tokens.len() {
            return Err(ProtocolError::new(
                "Number signed tokens does not match the number of requested tokens"
            ))
        }

        self.tokens.append(&mut unblinded_tokens);

        Ok(())
    }

    pub fn get_tokens(&mut self, n: usize) -> Result<Vec<UnblindedToken>, ProtocolError> {
        if n > self.tokens.len() {
            return Err(ProtocolError::new("Not enough buffered tokens"));
        };

        let mut tokens = vec![];
        for _ in 0..n {
            tokens.push(self.tokens.pop().unwrap());
        }

        Ok(tokens)
    }

    pub fn prepare_redemption(
        tokens: &[UnblindedToken],
        payload: String,
    ) -> (Vec<TokenPreimage>, Vec<VerificationSignature>) {
        let mut preimages = vec![];
        let mut verification_signatures = vec![];
        let payload_bytes = payload.as_bytes();

        for token in tokens {
            let preimage = token.t;
            let verification_key = token.derive_verification_key::<Sha512>();
            let verification_signature = verification_key.sign::<HmacSha512>(payload_bytes);

            preimages.push(preimage);
            verification_signatures.push(verification_signature);
        };

        (preimages, verification_signatures)
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}
