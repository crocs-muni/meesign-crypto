use crate::protocol::*;

use musig2;
use secp256k1::{Keypair, Secp256k1, PublicKey, SecretKey};
use rand::rngs::OsRng;

pub struct Signer<'a> {
    keypair: Keypair,
    key_agg_ctx: Option<KeyAggContext>,
    index: Option<usize>,
    first_round: Option<FirstRound>,
    second_round: Option<SecondRound<&'a str>>,
}

impl<'a> Signer<'a> {
    pub fn new() -> Self {

        let secp = Secp256k1::new();
        let mut rng = OsRng::default();
        let pair = secp.generate_keypair(&mut rng);

        Self {
            keypair: Keypair::from_secret_key(&secp, &pair.0),
            key_agg_ctx: None,
            index: None,
            first_round: None,
            second_round: None
        }
    }

    pub fn pubkey(&self) -> PublicKey {
        return self.keypair.public_key();
    }

    pub fn seckey(&self) -> SecretKey {
        return self.keypair.secret_key();
    }

    pub fn get_index(&self) -> usize {

        match self.index {
            None => panic!("Index not set"),
            Some(_) => {}
        }

        return self.index.unwrap();
    }

    pub fn generate_keyagg_context(&mut self, foreign_pubkeys: Vec<PublicKey>, tweak: Option<[u8;32]>, xonly: bool) {

        // Get public key shares sorted in lexigraphical order (BIP0327)
        let mut pubkeys: Vec<PublicKey> = foreign_pubkeys.clone();
        pubkeys.push(self.pubkey());
        let sorted_pubkeys:Vec<PublicKey>  = self.sort_pubkeys(pubkeys);

        // Set index of this signer in the sorted public keys
        self.set_index(sorted_pubkeys.clone());

        // Create key aggregation context
        let mut ctx = KeyAggContext::new(sorted_pubkeys).unwrap();

        // Apply tweak if provided
        match tweak {
            Some(tweak) => {
                let tweak_scalar = Scalar::from_slice(&tweak).unwrap();
                ctx = ctx.with_tweak(tweak_scalar, xonly).unwrap();
            }
            None => {}
        }

        // Store the key aggregation context
        match ctx {
            ctx => {
                self.key_agg_ctx = Some(ctx);
            }
        }
    }

    pub fn get_agg_pubkey(&self) -> PublicKey {
        if let Some(ctx) = self.key_agg_ctx.as_ref() {
            return ctx.aggregated_pubkey();
        } else {
            panic!("Key aggregation context not initialized");
        }
    }

    pub fn first_round(&mut self) {

        // Secret key share
        let seckey = self.seckey();

        // Create first round for this signer
        let first_round = musig2::FirstRound::new(
            self.key_agg_ctx.clone().unwrap(),
            &mut rand::rngs::OsRng,
            self.index.unwrap(),
            musig2::SecNonceSpices::new()
                .with_seckey(seckey)
        )
        .unwrap();

        // Store the first round
        self.first_round = Some(first_round);
    }

    // Add a publicn nonce of another signer to this signer's first round context
    pub fn add_pubnonce(&mut self, nonce_index: usize, pubnonce: PubNonce) {

        if let Some(fr) = self.first_round.as_mut() {

            if fr.is_complete() {
                panic!("First round already complete");
            }

            let res = fr.receive_nonce(nonce_index, pubnonce);

            match res {
                Ok(_) => {}
                Err(e) => {
                    panic!("Error adding pubnonce: {:?}", e);
                }
            }
        } else {
            panic!("First round not initialized");
        }
    }

    pub fn get_pubnonce(&self) -> PubNonce {
        if let Some(fr) = self.first_round.as_ref() {
            return fr.our_public_nonce();
        } else {
            panic!("First round not initialized");
        }
    }

    pub fn get_partial_signature(&self) -> PartialSignature {
        if let Some(sr) = self.second_round.as_ref() {
            return sr.our_signature();
        } else {
            panic!("Second round not initialized");
        }
    }

    pub fn second_round(&mut self, message: &'a str){

        if let Some(fr) = self.first_round.take() {
            if !fr.is_complete() {
                panic!("First round not complete");
            }

            if let Some(sr) = self.second_round.as_ref() {
                if sr.is_complete() {
                    panic!("Second round already complete");
                } else {
                    panic!("Second is already initialized");
                }
            }

            let second_round: SecondRound<&str> = fr.finalize::<&str>(self.seckey(),message).unwrap();
            self.second_round = Some(second_round);

        } else {
            panic!("First round not initialized");
        } 
    }

    pub fn receive_partial_signature(&mut self, signer_index: usize, partial_signature: PartialSignature) {
            
            if let Some(sr) = self.second_round.as_mut() {
                
                let res = sr.receive_signature(signer_index, partial_signature);

                match res {
                    Ok(_) => {}
                    Err(e) => {
                        panic!("Error adding partial signature: {:?}", e);
                    }
                }
            } else {
                panic!("Second round not initialized");
            }
    } 

    pub fn get_agg_signature(&mut self) -> CompactSignature {
        if let Some(sr) = self.second_round.take() {
            return sr.finalize().unwrap();
        } else {
            panic!("Second round not initialized");
        }
    }

    fn sort_pubkeys(&mut self, pubkeys: Vec<PublicKey>) -> Vec<PublicKey> {
        let mut pubkeys = pubkeys;
        pubkeys.sort_by(|a, b| a.serialize().cmp(&b.serialize()));

        return pubkeys;
    }

    fn set_index(&mut self, pubkeys: Vec<PublicKey>) {
        self.index = pubkeys.iter().position(|&x| x == self.pubkey());
    }
}