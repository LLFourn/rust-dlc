//! Module for working with DLC channels

use std::collections::HashMap;

use crate::{signatures_to_secret, util::get_sig_hash_msg, DlcTransactions, PartyParams, Payout};

use super::Error;
use bitcoin::{
    hashes::hash160::Hash, Address, Network, OutPoint, PrivateKey, PublicKey, Script, SigHashType,
    Transaction, TxIn, TxOut,
};
use miniscript::{Descriptor, DescriptorTrait};
use secp256k1_zkp::{
    rand::thread_rng, schnorrsig::Signature as SchnorrSignature, EcdsaAdaptorSignature,
    PublicKey as SecpPublicKey, Secp256k1, SecretKey, Signing, Verification,
};

// TODO(tibo): properly compute the extra weight
// We need to add the extra cost of buffer transaction including the more
// expensive CET satisfaction.
const BUFFER_TX_EXTRA_WEIGHT: usize = 500;

#[derive(Clone, Debug)]
///
pub struct RevokeParams {
    ///
    pub own_pk: PublicKey,
    ///
    pub publish_pk: PublicKey,
    ///
    pub revoke_pk: PublicKey,
}

///
pub struct DlcChannelTransactions {
    ///
    pub dlc_transactions: DlcTransactions,
    ///
    pub buffer_transaction: Transaction,
    ///
    pub buffer_script_pubkey: Script,
}

impl RevokeParams {
    ///
    pub fn from_priv_params<C: Signing>(
        secp: &Secp256k1<C>,
        priv_params: &RevokePrivateParams,
    ) -> Self {
        RevokeParams {
            own_pk: priv_params.own_priv.public_key(secp),
            publish_pk: priv_params.publish_priv.public_key(secp),
            revoke_pk: priv_params.revoke_priv.public_key(secp),
        }
    }

    fn get_pubkey_hashes(&self) -> (Hash, Hash, Hash) {
        (
            self.own_pk.pubkey_hash().as_hash(),
            self.publish_pk.pubkey_hash().as_hash(),
            self.revoke_pk.pubkey_hash().as_hash(),
        )
    }
}

///
pub struct RevokePrivateParams {
    ///
    pub own_priv: PrivateKey,
    ///
    pub publish_priv: PrivateKey,
    ///
    pub revoke_priv: PrivateKey,
}

impl RevokePrivateParams {
    ///
    pub fn new(network: Network) -> Self {
        Self {
            own_priv: PrivateKey::new(SecretKey::new(&mut thread_rng()), network),
            publish_priv: PrivateKey::new(SecretKey::new(&mut thread_rng()), network),
            revoke_priv: PrivateKey::new(SecretKey::new(&mut thread_rng()), network),
        }
    }

    ///
    pub fn public_params<C: Signing>(&self, secp: &Secp256k1<C>) -> RevokeParams {
        RevokeParams::from_priv_params(secp, self)
    }
}

///
pub fn create_buffer_transaction(
    fund_tx_in: &TxIn,
    descriptor: &Descriptor<PublicKey>,
    total_collateral: u64,
    lock_time: u32,
) -> Transaction {
    Transaction {
        version: super::TX_VERSION,
        lock_time,
        input: vec![fund_tx_in.clone()],
        output: vec![TxOut {
            value: total_collateral,
            script_pubkey: descriptor.script_pubkey(),
        }],
    }
}

///
pub fn get_tx_adaptor_signature<C: Signing>(
    secp: &Secp256k1<C>,
    tx: &Transaction,
    input_value: u64,
    script_pubkey: &Script,
    own_fund_sk: &SecretKey,
    other_publish_key: &SecpPublicKey,
) -> EcdsaAdaptorSignature {
    let sighash = get_sig_hash_msg(tx, 0, script_pubkey, input_value);

    EcdsaAdaptorSignature::encrypt(secp, &sighash, own_fund_sk, other_publish_key)
}

///
pub fn verify_tx_adaptor_signature<C: Verification>(
    secp: &Secp256k1<C>,
    tx: &Transaction,
    input_value: u64,
    script_pubkey: &Script,
    other_fund_pk: &SecpPublicKey,
    own_publish_key: &SecpPublicKey,
    adaptor_sig: &EcdsaAdaptorSignature,
) -> Result<(), Error> {
    let sighash = get_sig_hash_msg(tx, 0, script_pubkey, input_value);

    adaptor_sig.verify(secp, &sighash, other_fund_pk, own_publish_key)?;

    Ok(())
}

///
pub fn create_settle_transaction(
    fund_tx_in: &TxIn,
    offer_revoke_params: &RevokeParams,
    accept_revoke_params: &RevokeParams,
    offer_payout: u64,
    accept_payout: u64,
    csv_timelock: u32,
    lock_time: u32,
) -> Transaction {
    let offer_descriptor = settle_descriptor(
        offer_revoke_params,
        &accept_revoke_params.own_pk,
        csv_timelock,
    );
    let accept_descriptor = settle_descriptor(
        accept_revoke_params,
        &offer_revoke_params.own_pk,
        csv_timelock,
    );

    Transaction {
        version: super::TX_VERSION,
        lock_time,
        input: vec![fund_tx_in.clone()],
        output: vec![
            TxOut {
                value: offer_payout,
                script_pubkey: offer_descriptor.script_pubkey(),
            },
            TxOut {
                value: accept_payout,
                script_pubkey: accept_descriptor.script_pubkey(),
            },
        ],
    }
}

///
pub fn create_channel_transactions(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    offer_revoke_params: &RevokeParams,
    accept_revoke_params: &RevokeParams,
    payouts: &[Payout],
    refund_lock_time: u32,
    fee_rate_per_vb: u64,
    fund_lock_time: u32,
    cet_lock_time: u32,
    fund_output_serial_id: u64,
    cet_nsequence: u32,
) -> Result<DlcChannelTransactions, Error> {
    let extra_fee = super::util::weight_to_fee(BUFFER_TX_EXTRA_WEIGHT, fee_rate_per_vb);
    let (fund, funding_script_pubkey) = super::create_fund_transaction_with_fees(
        offer_params,
        accept_params,
        fee_rate_per_vb,
        fund_lock_time,
        fund_output_serial_id,
        extra_fee,
    )?;

    create_renewal_channel_transactions(
        offer_params,
        accept_params,
        offer_revoke_params,
        accept_revoke_params,
        &fund,
        &funding_script_pubkey,
        payouts,
        refund_lock_time,
        fee_rate_per_vb,
        cet_lock_time,
        cet_nsequence,
    )
}

///
pub fn create_renewal_channel_transactions(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    offer_revoke_params: &RevokeParams,
    accept_revoke_params: &RevokeParams,
    fund_tx: &Transaction,
    funding_script_pubkey: &Script,
    payouts: &[Payout],
    refund_lock_time: u32,
    fee_rate_per_vb: u64,
    cet_lock_time: u32,
    cet_nsequence: u32,
) -> Result<DlcChannelTransactions, Error> {
    let extra_fee = super::util::weight_to_fee(BUFFER_TX_EXTRA_WEIGHT, fee_rate_per_vb);

    let (fund_vout, fund_output) =
        super::util::get_output_for_script_pubkey(&fund_tx, &funding_script_pubkey.to_v0_p2wsh())
            .expect("to find the funding script pubkey");

    let outpoint = OutPoint {
        txid: fund_tx.txid(),
        vout: fund_vout as u32,
    };

    let tx_in = TxIn {
        previous_output: outpoint,
        sequence: super::util::get_sequence(cet_lock_time),
        script_sig: Script::new(),
        witness: Vec::new(),
    };

    let buffer_descriptor = buffer_descriptor(offer_revoke_params, accept_revoke_params);

    let buffer_transaction = create_buffer_transaction(
        &tx_in,
        &buffer_descriptor,
        fund_output.value - extra_fee,
        cet_lock_time,
    );

    let outpoint = OutPoint {
        txid: buffer_transaction.txid(),
        vout: 0,
    };

    let (cets, refund) = super::create_cets_and_refund_tx(
        offer_params,
        accept_params,
        outpoint,
        payouts,
        refund_lock_time,
        cet_lock_time,
        Some(cet_nsequence),
    )?;

    Ok(DlcChannelTransactions {
        dlc_transactions: DlcTransactions {
            fund: fund_tx.clone(),
            cets,
            refund,
            funding_script_pubkey: funding_script_pubkey.clone(),
        },
        buffer_transaction,
        buffer_script_pubkey: buffer_descriptor.script_code(),
    })
}

///
pub fn sign_cet<C: Signing>(
    secp: &Secp256k1<C>,
    cet: &mut Transaction,
    input_amount: u64,
    offer_params: &RevokeParams,
    accept_params: &RevokeParams,
    own_sk: &SecretKey,
    counter_pubkey: &PublicKey,
    adaptor_signature: &EcdsaAdaptorSignature,
    oracle_signatures: &[Vec<SchnorrSignature>],
) -> Result<(), Error> {
    let adaptor_secret = signatures_to_secret(oracle_signatures)?;
    let adapted_sig = adaptor_signature.decrypt(&adaptor_secret)?;
    let descriptor = buffer_descriptor(offer_params, accept_params);

    let own_sig = super::util::get_raw_sig_for_tx_input(
        secp,
        cet,
        0,
        &descriptor.script_code(),
        input_amount,
        &own_sk,
    );
    let own_pk = SecpPublicKey::from_secret_key(secp, own_sk);

    let sigs = HashMap::from([
        (
            PublicKey {
                key: own_pk,
                compressed: true,
            },
            (own_sig, SigHashType::All),
        ),
        (*counter_pubkey, (adapted_sig, SigHashType::All)),
    ]);

    descriptor
        .satisfy(&mut cet.input[0], sigs)
        .map_err(|_| Error::InvalidArgument)?;

    Ok(())
}

///
pub fn create_and_sign_punish_buffer_transaction<C: Signing>(
    secp: &Secp256k1<C>,
    offer_params: &RevokeParams,
    accept_params: &RevokeParams,
    own_sk: &SecretKey,
    counter_publish_sk: &SecretKey,
    counter_revoke_sk: &SecretKey,
    prev_tx: &Transaction,
    dest_address: &Address,
    lock_time: u32,
) -> Result<Transaction, Error> {
    let descriptor = buffer_descriptor(offer_params, accept_params);

    let tx_in = TxIn {
        previous_output: OutPoint {
            txid: prev_tx.txid(),
            vout: 0,
        },
        sequence: 0,
        script_sig: Script::new(),
        witness: Vec::new(),
    };

    // TODO(tibo): compute proper fee.
    let output_value = prev_tx.output[0].value - 1000;

    let mut tx = Transaction {
        version: super::TX_VERSION,
        lock_time,
        input: vec![tx_in],
        output: vec![TxOut {
            value: output_value,
            script_pubkey: dest_address.script_pubkey(),
        }],
    };

    let mut sigs = HashMap::new();

    for sk in &[&own_sk, &counter_publish_sk, &counter_revoke_sk] {
        let pk = PublicKey {
            key: SecpPublicKey::from_secret_key(secp, &sk),
            compressed: true,
        };

        let pkh = pk.pubkey_hash().as_hash();
        sigs.insert(
            pkh,
            (
                pk,
                (
                    super::util::get_raw_sig_for_tx_input(
                        secp,
                        &tx,
                        0,
                        &descriptor.script_code(),
                        prev_tx.output[0].value,
                        &sk,
                    ),
                    bitcoin::SigHashType::All,
                ),
            ),
        );
    }

    descriptor
        .satisfy(&mut tx.input[0], sigs)
        .map_err(|_| Error::InvalidArgument)?;

    Ok(tx)
}

/// Create and sign a punishment transaction for a revoked settle transaction.
pub fn create_and_sign_punish_settle_transaction<C: Signing>(
    secp: &Secp256k1<C>,
    offer_params: &RevokeParams,
    accept_params: &RevokeParams,
    own_sk: &SecretKey,
    counter_publish_sk: &SecretKey,
    counter_revoke_sk: &SecretKey,
    prev_tx: &Transaction,
    dest_address: &Address,
    csv_timelock: u32,
    lock_time: u32,
    is_offer: bool,
) -> Result<Transaction, Error> {
    let (own_params, counter_params) = if is_offer {
        (offer_params, accept_params)
    } else {
        (accept_params, offer_params)
    };

    let descriptor = settle_descriptor(&counter_params, &own_params.own_pk, csv_timelock);

    let vout = if is_offer { 1 } else { 0 };

    let tx_in = TxIn {
        previous_output: OutPoint {
            txid: prev_tx.txid(),
            vout,
        },
        sequence: 0,
        script_sig: Script::new(),
        witness: Vec::new(),
    };

    let input_value = prev_tx.output[vout as usize].value;

    let mut tx = Transaction {
        version: super::TX_VERSION,
        lock_time,
        input: vec![tx_in],
        output: vec![TxOut {
            // TODO(tibo): need to compute proper fee
            value: input_value - 1000,
            script_pubkey: dest_address.script_pubkey(),
        }],
    };

    let mut sigs = HashMap::new();

    for sk in &[&own_sk, &counter_publish_sk, &counter_revoke_sk] {
        let pk = PublicKey {
            key: SecpPublicKey::from_secret_key(secp, &sk),
            compressed: true,
        };
        sigs.insert(
            pk,
            (
                super::util::get_raw_sig_for_tx_input(
                    secp,
                    &tx,
                    0,
                    &descriptor.script_code(),
                    input_value,
                    &sk,
                ),
                bitcoin::SigHashType::All,
            ),
        );
    }

    descriptor
        .satisfy(&mut tx.input[0], sigs)
        .map_err(|_| Error::InvalidArgument)?;

    Ok(tx)
}

/// Create a transaction for collaboratively closing a channel.
pub fn create_collaborative_close_transaction(
    offer_params: &PartyParams,
    offer_payout: u64,
    accept_params: &PartyParams,
    accept_payout: u64,
    fund_outpoint: OutPoint,
    _fund_output_amount: u64,
) -> Transaction {
    let input = TxIn {
        previous_output: fund_outpoint.clone(),
        witness: Vec::new(),
        script_sig: Script::new(),
        sequence: crate::util::DISABLE_LOCKTIME,
    };

    //TODO(tibo): add fee re-payment
    let offer_output = TxOut {
        value: offer_payout,
        script_pubkey: offer_params.payout_script_pubkey.clone(),
    };

    let accept_output = TxOut {
        value: accept_payout,
        script_pubkey: accept_params.payout_script_pubkey.clone(),
    };

    let mut output: Vec<TxOut> = if offer_params.payout_serial_id < accept_params.payout_serial_id {
        vec![offer_output, accept_output]
    } else {
        vec![accept_output, offer_output]
    };

    output = crate::util::discard_dust(output, crate::DUST_LIMIT);

    Transaction {
        version: crate::TX_VERSION,
        lock_time: 0,
        input: vec![input],
        output,
    }
}

///
fn buffer_descriptor(
    offer_revoke_params: &RevokeParams,
    accept_revoke_params: &RevokeParams,
) -> Descriptor<PublicKey> {
    let (offer_pkh, offer_publish_pkh, offer_revoke_pkh) = offer_revoke_params.get_pubkey_hashes();
    let (accept_pkh, accept_publish_pkh, accept_revoke_pkh) =
        accept_revoke_params.get_pubkey_hashes();

    let offer_pk = offer_revoke_params.own_pk;
    let accept_pk = accept_revoke_params.own_pk;

    let (first_pk, second_pk) = if offer_pk < accept_pk {
        (offer_pk, accept_pk)
    } else {
        (accept_pk, offer_pk)
    };
    // heavily inspired by: https://github.com/comit-network/maia/blob/main/src/protocol.rs#L283
    // policy: or(and(pk(offer_pk),pk(accept_pk)),or(and(pk(offer_pk),and(pk(accept_publish_pk), pk(accept_rev_pk))),and(pk(offer_pk),and(pk(offer_publish_pk),pk(offer_rev_pk)))))
    let script = format!("wsh(c:andor(pk({first_pk}),pk_k({second_pk}),or_i(and_v(v:pkh({offer_pk_hash}),and_v(v:pkh({accept_publish_pk_hash}),pk_h({accept_revoke_pk_hash}))),and_v(v:pkh({accept_pk_hash}),and_v(v:pkh({offer_publish_pk_hash}),pk_h({offer_revoke_pk_hash}))))))",
        first_pk = first_pk,
        second_pk = second_pk,
        offer_pk_hash = offer_pkh,
        accept_pk_hash = accept_pkh,
        accept_publish_pk_hash = accept_publish_pkh,
        accept_revoke_pk_hash = accept_revoke_pkh,
        offer_publish_pk_hash = offer_publish_pkh,
        offer_revoke_pk_hash = offer_revoke_pkh);
    script.parse().expect("a valid miniscript")
}

fn settle_descriptor(
    payee_revoke_params: &RevokeParams,
    counter_pk: &PublicKey,
    csv_timelock: u32,
) -> Descriptor<PublicKey> {
    // policy: or(and(pk(payee_pk), older(csv_timelock)), and(pk(counter_pk), and(pk(payee_publish_pk), pk(payee_revoke_pk))))
    let script = format!("wsh(andor(pk({payee_pk}),older({csv_timelock}),and_v(v:pk({counter_pk}),and_v(v:pk({payee_publish_pk}),pk({payee_revoke_pk})))))",
        payee_pk = payee_revoke_params.own_pk,
        csv_timelock = csv_timelock,
        counter_pk = counter_pk,
        payee_publish_pk = payee_revoke_params.publish_pk,
        payee_revoke_pk = payee_revoke_params.revoke_pk,
    );
    script.parse().expect("a valid miniscript")
}

#[cfg(test)]
mod tests {
    use std::{iter::FromIterator, str::FromStr};

    use secp256k1_zkp::SECP256K1;

    use super::*;

    #[test]
    fn create_and_sign_penalty_from_buffer_transaction_test() {
        let offer_priv_params = RevokePrivateParams::new(Network::Regtest);
        let accept_priv_params = RevokePrivateParams::new(Network::Regtest);
        let offer_params = offer_priv_params.public_params(SECP256K1);
        let accept_params = accept_priv_params.public_params(SECP256K1);
        let dest_address = Address::p2pkh(
            &PublicKey::from_private_key(
                SECP256K1,
                &PrivateKey::new(SecretKey::new(&mut thread_rng()), Network::Regtest),
            ),
            Network::Regtest,
        );
        let total_collateral = 100000000;

        let descriptor = buffer_descriptor(&offer_params, &accept_params);

        let buffer_tx =
            create_buffer_transaction(&TxIn::default(), &descriptor, total_collateral, 0);

        // Offerer can create and sign with accepter revocation and publish secret.
        create_and_sign_punish_buffer_transaction(
            SECP256K1,
            &offer_params,
            &accept_params,
            &offer_priv_params.own_priv.key,
            &accept_priv_params.publish_priv.key,
            &accept_priv_params.revoke_priv.key,
            &buffer_tx,
            &dest_address,
            0,
        )
        .expect("to be able to create and sign the punish transaction");

        // Accepter can create and sign with offerer revocation and publish secret.
        create_and_sign_punish_buffer_transaction(
            SECP256K1,
            &offer_params,
            &accept_params,
            &accept_priv_params.own_priv.key,
            &offer_priv_params.publish_priv.key,
            &offer_priv_params.revoke_priv.key,
            &buffer_tx,
            &dest_address,
            0,
        )
        .expect("to be able to create and sign the punish transaction");

        // Offerer and accepter cannot satisfy with only their parameters
        assert!(create_and_sign_punish_buffer_transaction(
            SECP256K1,
            &offer_params,
            &accept_params,
            &offer_priv_params.own_priv.key,
            &offer_priv_params.publish_priv.key,
            &offer_priv_params.revoke_priv.key,
            &buffer_tx,
            &dest_address,
            0
        )
        .is_err());

        // Offerer and accepter cannot satisfy with only their parameters
        assert!(create_and_sign_punish_buffer_transaction(
            SECP256K1,
            &offer_params,
            &accept_params,
            &accept_priv_params.own_priv.key,
            &accept_priv_params.publish_priv.key,
            &accept_priv_params.revoke_priv.key,
            &buffer_tx,
            &dest_address,
            0
        )
        .is_err());
    }

    #[test]
    fn two_parties_sigs_satisfy_buffer_descriptor_test() {
        let offer_priv_params = RevokePrivateParams::new(Network::Regtest);
        let accept_priv_params = RevokePrivateParams::new(Network::Regtest);
        let offer_params = offer_priv_params.public_params(SECP256K1);
        let accept_params = accept_priv_params.public_params(SECP256K1);

        let descriptor = buffer_descriptor(&offer_params, &accept_params);

        // Use random signature as it doesn't matter.
        let sig = (
            secp256k1_zkp::Signature::from_str(
                "3045\
             0221\
             00f7c3648c390d87578cd79c8016940aa8e3511c4104cb78daa8fb8e429375efc1\
             0220\
             531d75c136272f127a5dc14acc0722301cbddc222262934151f140da345af177",
            )
            .unwrap(),
            bitcoin::SigHashType::All,
        );

        let satisfier = HashMap::from_iter(vec![
            (offer_params.own_pk, sig.clone()),
            (accept_params.own_pk, sig.clone()),
        ]);

        descriptor
            .satisfy(&mut TxIn::default(), satisfier)
            .expect("to be able to satisfy the descriptor");
    }

    #[test]
    fn create_and_sign_penalty_from_settle_transaction_test() {
        let offer_priv_params = RevokePrivateParams::new(Network::Regtest);
        let accept_priv_params = RevokePrivateParams::new(Network::Regtest);
        let offer_params = offer_priv_params.public_params(SECP256K1);
        let accept_params = accept_priv_params.public_params(SECP256K1);
        let dest_address = Address::p2pkh(
            &PublicKey::from_private_key(
                SECP256K1,
                &PrivateKey::new(SecretKey::new(&mut thread_rng()), Network::Regtest),
            ),
            Network::Regtest,
        );
        let payout = 100000000;
        let csv_timelock = 100;
        let settle_tx = create_settle_transaction(
            &TxIn::default(),
            &offer_params,
            &accept_params,
            payout,
            payout,
            csv_timelock,
            0,
        );

        // Offerer can create and sign with accepter revocation and publish secret.
        create_and_sign_punish_settle_transaction(
            SECP256K1,
            &offer_params,
            &accept_params,
            &offer_priv_params.own_priv.key,
            &accept_priv_params.publish_priv.key,
            &accept_priv_params.revoke_priv.key,
            &settle_tx,
            &dest_address,
            csv_timelock,
            0,
            true,
        )
        .expect("to be able to create and sign the punish transaction");

        // Accepter can create and sign with offerer revocation and publish secret.
        create_and_sign_punish_settle_transaction(
            SECP256K1,
            &offer_params,
            &accept_params,
            &accept_priv_params.own_priv.key,
            &offer_priv_params.publish_priv.key,
            &offer_priv_params.revoke_priv.key,
            &settle_tx,
            &dest_address,
            csv_timelock,
            0,
            false,
        )
        .expect("to be able to create and sign the punish transaction");

        // Offerer and accepter cannot satisfy with only their parameters
        assert!(create_and_sign_punish_settle_transaction(
            SECP256K1,
            &offer_params,
            &accept_params,
            &offer_priv_params.own_priv.key,
            &offer_priv_params.publish_priv.key,
            &offer_priv_params.revoke_priv.key,
            &settle_tx,
            &dest_address,
            csv_timelock,
            0,
            true
        )
        .is_err());

        // Offerer and accepter cannot satisfy with only their parameters
        assert!(create_and_sign_punish_settle_transaction(
            SECP256K1,
            &offer_params,
            &accept_params,
            &accept_priv_params.own_priv.key,
            &accept_priv_params.publish_priv.key,
            &accept_priv_params.revoke_priv.key,
            &settle_tx,
            &dest_address,
            csv_timelock,
            0,
            false
        )
        .is_err());
    }

    #[test]
    fn one_party_sig_satisfies_settle_descriptor_test() {
        let offer_priv_params = RevokePrivateParams::new(Network::Regtest);
        let accept_priv_params = RevokePrivateParams::new(Network::Regtest);
        let offer_params = offer_priv_params.public_params(SECP256K1);
        let accept_params = accept_priv_params.public_params(SECP256K1);
        let csv = 100;

        let descriptor = settle_descriptor(&offer_params, &accept_params.own_pk, csv);

        // Use random signature as it doesn't matter.
        let sig = (
            secp256k1_zkp::Signature::from_str(
                "3045\
             0221\
             00f7c3648c390d87578cd79c8016940aa8e3511c4104cb78daa8fb8e429375efc1\
             0220\
             531d75c136272f127a5dc14acc0722301cbddc222262934151f140da345af177",
            )
            .unwrap(),
            bitcoin::SigHashType::All,
        );

        let satisfier = HashMap::from_iter(vec![(offer_params.own_pk, sig.clone())]);

        descriptor
            .satisfy(
                &mut TxIn {
                    sequence: csv + 1,
                    ..Default::default()
                },
                (satisfier, miniscript::miniscript::satisfy::Older(csv)),
            )
            .expect("to be able to satisfy the descriptor");
    }
}
