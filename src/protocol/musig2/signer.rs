use core::panic;
use std::convert::TryInto;

use musig2::errors::VerifyError;
use musig2::{AdaptorSignature, AggNonce, CompactSignature, FirstRound, KeyAggContext, LiftedSignature, PartialSignature, PubNonce, SecondRound};
use musig2::secp::{MaybeScalar, Scalar, MaybePoint};
use musig2::adaptor::{aggregate_partial_signatures, verify_partial};
use rand::RngCore;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use rand::rngs::OsRng;

// Musig2 Signer Util

const DUMMY_SKEY: [u8; 32] = [0; 32];

#[derive(Serialize, Deserialize, Clone)]
pub struct Signer {
    with_card: bool,
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
    // Public nonce of the signer (with card only)
    pubnonce: Option<PubNonce>,
    // Pub nonces of other signers
    pub_nonces: Option<Vec<(usize, PubNonce)>>,
    // Partial signature of the signer (with card only)
    partial_signature: Option<PartialSignature>,
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
            with_card: false,
            pubkey: keypair.public_key(),
            seckey: Some(keypair.secret_key()),
            key_agg_ctx: None,
            index: None,
            agg_signature: None,
            sec_nonce: None,
            pubnonce: None,
            pub_nonces: None,
            message: None,
            partial_signature: None,
            partial_signatures: None,
        }
    }

    pub fn new_from_card(pubkey: PublicKey) -> Self {
        
        let pubkey = pubkey;

        Self {
            with_card: true,
            pubkey: pubkey,
            seckey: None,
            key_agg_ctx: None,
            index: None,
            agg_signature: None,
            sec_nonce: None,
            pubnonce: None,
            pub_nonces: None,
            message: None,
            partial_signature: None,
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

    pub fn set_partial_signature(&mut self, partial_signature: PartialSignature) -> Result<(), String> {
        if self.with_card {
            self.partial_signature = Some(partial_signature);
            Ok(())
        } else {
            Err("Only card based signers can set their partial signature.".into())
        }
    }

    pub fn set_pubnonce(&mut self, pubnonce: PubNonce) -> Result<(), String> {
        if self.with_card {
            self.pubnonce = Some(pubnonce);
            Ok(())
        } else {
            Err("Only card based signers can set their pubnonce.".into())
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
                let seckey = if self.with_card {SecretKey::from_slice(&DUMMY_SKEY).unwrap()} 
                                            else {self.seckey()};

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

    pub fn get_pubnonce(&self) -> Result<PubNonce, String> {

        if self.with_card {
            match &self.pubnonce {
                Some(pubnonce) => {
                    return Ok(pubnonce.clone());
                }
                None => {
                    return Err("No pubnonce set for card signer".into());
                }
            }
        }

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

    pub fn get_aggnonce(&self) -> Result<AggNonce, String> {

        match &self.pub_nonces {
            None => return Err("Pubnonces not initialized".into()),
            Some(pub_nonces) => {
                let mut pubnonces_all = pub_nonces.clone();
                pubnonces_all.push((self.get_index(), self.get_pubnonce()?));
                let agg_nonce = pubnonces_all.iter().map(|(_, pubnonce)| pubnonce).sum();
                return Ok(agg_nonce);
            }
        };
    }

    pub fn second_round(&mut self, message: &Vec<u8>, pubnonces: Vec<(usize, PubNonce)>) {
        self.message = Some(message.clone());
        self.pub_nonces = Some(pubnonces.clone());
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

        let second_round: SecondRound<Vec<u8>>;   
        
        if self.with_card {
            return Err("Card signers cant generate second round.".into());
        } else {
            second_round = first_round.finalize::<Vec<u8>>(self.seckey(), message).unwrap();
        }

        Ok(second_round)
    }

    pub fn get_partial_signature(&mut self) -> PartialSignature {

        if self.with_card {
            match &self.partial_signature {
                Some(partial_signature) => {
                    return partial_signature.clone();
                }
                None => {
                    panic!("No pubnonce set for card signer");
                }
            }
        }

        let second_round = match self.second_round_internal() {
            Ok(sr) => sr,
            Err(_) => panic!("Second round not initialized"),
        };

        return second_round.our_signature();
    }

    pub fn receive_partial_signatures(&mut self, partial_signatures: Vec<(usize, PartialSignature)>) {
        self.partial_signatures = Some(partial_signatures);
    }

    pub fn get_agg_signature(&mut self) -> Result<CompactSignature, String> {

        let partial_signatures = match &self.partial_signatures {
            Some(partial_signatures) => partial_signatures.clone(),
            None => return Err("Partial signatures not initialized".into()),
        };

        let agg_signature = if self.with_card {
            self.get_agg_signature_with_card(partial_signatures)
        } else {
            self.get_agg_signature_no_card(partial_signatures)
        };

        // Erase nonces for security reasons
        self.sec_nonce = None;
        self.pub_nonces = None;
        self.partial_signatures = None;

        return agg_signature;
    }

    fn get_agg_signature_no_card (
        &mut self, 
        partial_signatures: Vec<(usize, MaybeScalar)>
    ) -> Result<CompactSignature, String> {

        let mut sr = match self.second_round_internal() {
            Ok(sr) => sr,
            Err(_) => return Err("Second round not initialized".into()),
        };

        for (signer_index, partial_signature) in partial_signatures {
            match sr.receive_signature(signer_index, partial_signature) {
                Ok(_) => {}
                Err(_) => {
                    return Err("Error receiving partial signature".into());
                }
            }
        }

        return Ok(sr.finalize().unwrap());
    }


    // Insipired by [`musig2::SecondRound::finalize`] method
    fn get_agg_signature_with_card<T> (
        &mut self,
        partial_signatures: Vec<(usize, MaybeScalar)>
    ) -> Result<T, String>
    where
        T: From<LiftedSignature>, 
    {

        //TODO: Add partial signature correctness check
        // for partial_signature in partial_signatures {
        //     verify_partial(
        //        &self.key_agg_ctx.clone().unwrap(),
        //         partial_signature.1,
        //         &self.get_aggnonce()?, 
        //         MaybePoint::Infinity,
        //         &self.key_agg_ctx,
        //         individual_pubnonce, 
        //         message);
        // }

        let mut sorted_partial_signatures = partial_signatures.clone();
        sorted_partial_signatures.push((self.get_index(), self.get_partial_signature()));
        sorted_partial_signatures.sort_by(|a, b| a.0.cmp(&b.0));
        let sorted_partial_signatures: Vec<PartialSignature> = sorted_partial_signatures
            .iter()
            .map(|x| x.1)
            .collect();

        let aggnonce = self.get_aggnonce()?;
        let message = self.message.as_ref().unwrap();

        let sig = aggregate_partial_signatures(
            &self.key_agg_ctx.clone().unwrap(),
            &aggnonce,
            MaybePoint::Infinity,
            sorted_partial_signatures,
            &message
        );

        let agg_sig = sig
            .map_err(|e| e.to_string())?
            .adapt(MaybeScalar::Zero)
            .expect("finalizing with empty adaptor should never result in an adaptor failure");

        return Ok(T::from(agg_sig));
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