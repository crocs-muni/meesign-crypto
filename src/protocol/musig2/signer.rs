use core::panic;

use musig2::{CompactSignature, FirstRound, KeyAggContext, PartialSignature, PubNonce, SecondRound};
use musig2::secp::{MaybeScalar, Scalar};
use rand::RngCore;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use rand::rngs::OsRng;

// Musig2 Signer Util

#[derive(Serialize, Deserialize, Clone)]
pub struct Signer {
    // Public key share
    pubkey: PublicKey,
    // Private key share
    seckey: Option<SecretKey>,
    key_agg_ctx: Option<KeyAggContext>,
    // Index of the signer
    index: Option<usize>,
    // Aggregated signature
    agg_signature: Option<CompactSignature>, 
    // Secret nonce
    sec_nonce: Option<[u8; 32]>, 
    // Pub nonces
    pub_nonces: Option<Vec<(usize, PubNonce)>>, 
    // Partial signatures
    partial_signatures: Option<Vec<(usize, PartialSignature)>>, 
    // Message to be signed
    message: Option<Vec<u8>>, 
}

impl Signer {
    pub fn new() -> Self {

        let secp = Secp256k1::new();
        let mut rng = OsRng::default();
        let pair = secp.generate_keypair(&mut rng); 
        let keypair = Keypair::from_secret_key(&secp, &pair.0);

        Self {
            pubkey: keypair.public_key(),
            seckey: Some(keypair.secret_key()),
            key_agg_ctx: None,
            index: None,
            agg_signature: None,
            sec_nonce: None,
            pub_nonces: None,
            message: None,
            partial_signatures: None,
        }
    }

    pub fn new_from_card(pubkey: PublicKey) -> Self {
        
        let pubkey = pubkey;

        Self {
            pubkey: pubkey,
            seckey: None,
            key_agg_ctx: None,
            index: None,
            agg_signature: None,
            sec_nonce: None,
            pub_nonces: None,
            message: None,
            partial_signatures: None,
        }
    }

    pub fn get_index(&self) -> usize {

        match self.index {
            None => panic!("Index not set"),
            Some(_) => {}
        }

        return self.index.unwrap();
    }

    pub fn receive_partial_signatures(&mut self, partial_signatures: Vec<(usize, PartialSignature)>) {
        self.partial_signatures = Some(partial_signatures);
    }

    // Share public key
    pub fn pubkey(&self) -> PublicKey {
        return self.pubkey;
    }

    // Share secret key
    fn seckey(&self) -> SecretKey {

        match self.seckey {
            None => panic!("Secret key not set"),
            Some(seckey) => return seckey,
        }
    }

    pub fn generate_key_agg_ctx(&mut self, all_pubkeys: Vec<PublicKey>, tweak: Option<[u8;32]>, xonly: bool) {

        // Get public key shares sorted in lexigraphical order (BIP0327)
        let mut pubkeys: Vec<PublicKey> = all_pubkeys.clone();
        pubkeys.push(self.pubkey());
        let sorted_pubkeys: Vec<PublicKey>  = self.sort_pubkeys(pubkeys);

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

        self.key_agg_ctx = Some(ctx);

        }

    pub fn get_agg_pubkey(&self) -> PublicKey {
        if let Some(ctx) = self.key_agg_ctx.as_ref() {
            return ctx.aggregated_pubkey();
        } else {
            panic!("Aggregated public key not initialized.");
        }
    }

    pub fn get_coef_a(&self) -> MaybeScalar {
        if let Some(ctx) = self.key_agg_ctx.as_ref() {
            return ctx.key_coefficient(self.pubkey()).unwrap();
        } else {
            panic!("Aggregated public key not initialized.");
        }
    }

    pub fn first_round(&mut self) {

        // Create an instance of OsRng
        let mut rng = OsRng;

        // Generate a random 32-byte array
        let mut nonce_seed = [0u8; 32];
        rng.fill_bytes(&mut nonce_seed);

        self.sec_nonce = Some(nonce_seed);
    }

    fn first_round_internal(&self) -> Result<FirstRound, String> {

        match self.sec_nonce {

            None => {
                return Err("Secret nonce not initialized".into());
            }

            Some(sec_nonce) => {
                 // Secret key share
                let seckey = self.seckey();

                // Create first round for this signer
                let first_round = musig2::FirstRound::new(
                    self.key_agg_ctx.clone().unwrap(),
                    sec_nonce,
                    self.get_index(),
                    musig2::SecNonceSpices::new()
                        .with_seckey(seckey)
                )
                .unwrap();

                // Store the first round
                return Ok(first_round);
            }
        }
    }

    pub fn get_pubnonce(&mut self) -> Result<PubNonce, String> {
        
        let first_round = self.first_round_internal();

        match first_round {
            Ok(first_round) => {
                return Ok(first_round.our_public_nonce());
            }
            Err(_) => {
                return Err("Error getting pubnonce".into());
            }
        }
    }

    // Add a public nonce of another signer to this signer's first round context
    fn add_pubnonce(&mut self, nonce_index: &usize, pubnonce: PubNonce, first_round: &mut FirstRound) {

            let index: usize = nonce_index.clone();

            let res = first_round.receive_nonce(index, pubnonce);

            match res {
                Ok(_) => {}
                Err(e) => {
                    panic!("Error adding pubnonce: {:?}", e);
                }
            }
    }

    fn second_round_internal(&mut self) -> Result<SecondRound<Vec<u8>>, String> {

        let pubnonces = match &self.pub_nonces {
            Some(pubnonces) => pubnonces.clone(),
            None => return Err("Pubnonces not initialized".into()),
        };
    
        let message = match &self.message {
            Some(message) => message.clone(),
            None => return Err("Message not initialized".into()),
        };
    
        let mut first_round = self.first_round_internal().unwrap();
    
        for (index, pubnonce) in pubnonces.iter() {
            self.add_pubnonce(&index, pubnonce.clone(), &mut first_round);
        }
    
        let second_round: SecondRound<Vec<u8>> = first_round.finalize::<Vec<u8>>(self.seckey(), message).unwrap();
        Ok(second_round)
    }

    pub fn second_round(&mut self, message: &Vec<u8>, pubnonces: Vec<(usize, PubNonce)>) {
        self.message = Some(message.clone());
        self.pub_nonces = Some(pubnonces.clone());
    }

    pub fn get_partial_signature(&mut self) -> PartialSignature {

        let second_round = match self.second_round_internal() {
            Ok(sr) => sr,
            Err(_) => panic!("Second round not initialized"),
        };

        return second_round.our_signature();
    }

    pub fn get_agg_signature(&mut self) -> Result<CompactSignature, String> {

        let mut sr = match self.second_round_internal() {
            Ok(sr) => sr,
            Err(_) => return Err("Second round not initialized".into()),
        };

        let partial_signatures = match &self.partial_signatures {
            Some(partial_signatures) => partial_signatures.clone(),
            None => return Err("Partial signatures not initialized".into()),
        };

        for (signer_index, partial_signature) in partial_signatures {
            match sr.receive_signature(signer_index, partial_signature) {
                Ok(_) => {}
                Err(e) => {
                    return Err(format!("Error receiving signature: {:?}", e));
                }
            }
        }

        let agg_signature = sr.finalize().unwrap();

        // Erase nonces for security reasons
        self.sec_nonce = None;
        self.pub_nonces = None;
        self.partial_signatures = None;

        return Ok(agg_signature);
    }

    fn sort_pubkeys(&mut self, pubkeys: Vec<PublicKey>) -> Vec<PublicKey> {
        let mut pubkeys = pubkeys;
        pubkeys.sort_by(|a, b| a.serialize().cmp(&b.serialize()));

        return pubkeys;
    }

    fn set_index(&mut self, pubkeys: Vec<PublicKey>) {
        let index = pubkeys.iter().position(|&x| x == self.pubkey());

        if index == None {
            panic!("Public key not found in the list of public keys");
        }

        self.index = index;
    }
}