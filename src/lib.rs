pub mod privacypass;
pub mod traits;

#[cfg(test)]
mod tests {
    use crate::privacypass::wallet::*;
    use crate::privacypass::issuer::*;
    use crate::privacypass::models::*;

    use challenge_bypass_ristretto::voprf::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn e2e_privacypass() {
        let mut rng = OsRng;

        let mut pp_wallet = Wallet::new();

        let signing_key = SigningKey::random(&mut rng);
        let mut issuer = Issuer::new(&signing_key.to_bytes());

        let (raw_tokens, blinded_tokens) = Wallet::generate_blinded_tokens(10);
        let signing_request = SigningRequest{ blinded_tokens: blinded_tokens.clone() };

        let signing_response = issuer.sign_tokens(signing_request).unwrap();

        let _signed_tokens = pp_wallet.process_signed_tokens(
            &signing_response.signed_tokens,
            signing_response.batch_proof,
            signing_response.public_key.unwrap(),
            &raw_tokens,
            &blinded_tokens,
        ).unwrap();

        // OK
        let payload = "test".to_string();
        let tokens = pp_wallet.get_tokens(1).unwrap();
        let (preimages, verification_signatures) = Wallet::prepare_redemption(&tokens, payload.clone());

        let redeem_request = RedeemRequest{
            preimages,
            verification_signatures,
            payload: payload.as_bytes().to_vec(),
        };

        let (_, redeemed_preimages) = issuer.process_redeem_tokens(&redeem_request);

        // Double spending!
        let payload = "test double spending".to_string();
        let (preimages, verification_signatures) = Wallet::prepare_redemption(&tokens, payload.clone());

        let redeem_request = RedeemRequest{
            preimages,
            verification_signatures,
            payload: payload.as_bytes().to_vec(),
        };

        let (_, redeemed_preimages_2) = issuer.process_redeem_tokens(&redeem_request);

        assert_eq!(
            redeemed_preimages[0], redeemed_preimages_2[0],
            "Issuer should be able to detect double spending"
        );
    }
}
