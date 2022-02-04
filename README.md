## Private Humamity Tokens

[![](https://img.shields.io/badge/Version-0.1.0--alpha-brightgreen)](https://crates.io/crates/htokens-rs) [![](https://docs.rs/htokens-rs/badge.svg)](https://docs.rs/htokens-rs) ![](https://github.com/gpestana/htokens-rs/actions/workflows/tests.yml/badge.svg)

`htokens-rs` implements a suite of verifiable anonymous credentials that can be used by applications and systems to enhance/provide privacy to users without impacting practicality.

In general, the schemes implemented by htokens-rs have three main participants: an issuer , a wallet and a verifier. The issuer, *issues* htokens to a particular wallet. The wallet stores and utilizes issued tokens by making *claims* about tokens to third parties. Finally, a verifier *verifies* whether the claims made by the wallet about their token are valid. Importantly, the wallet identity may remain hidden when the claims about their tokens are verified.

The claims can be, for example, of the form `"This token has been issued by Issuer X in the past month"` or `"Issuer X of this token guarantees that the owner is a human based on properties Z and Y"`, etc. In general, these schemes allow wallets to fetch tokens from issuers and prove properties about themself to verifiers without disclosing their own identity.

While htokens are not necessarily issued/verified by a smart contract, many of the schemes implemented in this crate allow for smart contract integration (WIP).

The htoken-rs library supports (or will support) the following schemes:

- Third-party issued credentials with public and private metadata and private verifiability (e.g. [Privacy Pass](https://datatracker.ietf.org/wg/privacypass/about/))
- Third-party issued credentials with public and private metadata and public verifiability
- Self-issued credentials with private verifiability
- Self-issued credentials with public verifiability

In addition, `htokens-wallet-rs` implements an API and CLI for users to manage and use their credentials.

**Application examples**:

- Privacy Pass tokens and CAPTCHAs
- Privacy-preserving humanity attestation
- Private access management and delegation
- Smart contract access/reputation control