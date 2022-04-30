use bitcoin::hashes::Hash;
use bitcoin::OutPoint;
use bitcoin::Script;
use bitcoin::WPubkeyHash;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dlc::create_dlc_transactions;
use dlc::DlcTransactions;
use dlc::PartyParams;
use dlc::Payout;
use dlc::TxInputInfo;
use dlc_manager::contract::contract_info::ContractInfo;
use dlc_manager::contract::ContractDescriptor;
use dlc_messages::oracle_msgs::EventDescriptor;
use dlc_messages::oracle_msgs::OracleAnnouncement;
use dlc_messages::oracle_msgs::OracleEvent;
use secp256k1_zkp::{
    global::SECP256K1,
    rand::thread_rng,
    schnorrsig::{KeyPair, PublicKey, Signature},
    SecretKey,
};
use std::str::FromStr;


/// === CHANGE ONLY THESE ONES ===
const NB_ORACLES: usize = 3;
/// The number of oracles required to be in agreement to close the contract.
const THRESHOLD: usize = 7;
/// The totoal number of outcomes
const N_OUTCOMES: usize = 1024;
/// === DO NOT CHANGE ANYTHING BELOW HERE


/// The number of digits used to represent outcome values.
const NB_DIGITS: usize = 1;
/// The number of oracles used for the contract.
/// The ID of the event.
const EVENT_ID: &str = "Test";
/// The total collateral value locked in the contract.
const TOTAL_COLLATERAL: u64 = 10240;



fn create_contract_descriptor() -> ContractDescriptor {
    use dlc::EnumerationPayout;
    use dlc_manager::contract::enum_descriptor::EnumDescriptor;
    ContractDescriptor::Enum(
        EnumDescriptor {
            outcome_payouts: (0..N_OUTCOMES).map(|i| EnumerationPayout {
                outcome: i.to_string(),
                payout: Payout {
                    offer: (i * 10) as u64,
                    accept: TOTAL_COLLATERAL - (i * 10) as u64
                }
            }).collect(),
        }
    )
}

fn get_schnorr_pubkey() -> PublicKey {
    PublicKey::from_keypair(SECP256K1, &KeyPair::new(SECP256K1, &mut thread_rng()))
}

fn get_pubkey() -> secp256k1_zkp::PublicKey {
    secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &SecretKey::new(&mut thread_rng()))
}

fn get_p2wpkh_script_pubkey() -> Script {
    Script::new_v0_wpkh(&WPubkeyHash::hash(&get_pubkey().serialize()))
}

fn create_oracle_announcements() -> Vec<OracleAnnouncement> {
    use dlc_messages::oracle_msgs::EnumEventDescriptor;
    (0..NB_ORACLES).map(|_| {
            OracleAnnouncement {
            announcement_signature: Signature::from_str("859833d34b9cbd7c0a898693a289af434c74ad1d65e15c67d1b1d3bf74d9ee85cbd5258da5e91815da9989185c8bc9b026ce6f6598c1b2fb127c1bb1a6bef74a").unwrap(),
            oracle_public_key: get_schnorr_pubkey(),
            oracle_event: OracleEvent{
                event_descriptor: EventDescriptor::EnumEvent(EnumEventDescriptor {
                    outcomes: (0..N_OUTCOMES).map(|i| i.to_string()).collect()
                }),
                oracle_nonces: (0..NB_DIGITS).map(|_| get_schnorr_pubkey()).collect(),
                event_maturity_epoch: 1234567,
                event_id: EVENT_ID.to_string(),
        }}}).collect()
}

fn create_contract_info() -> ContractInfo {
    let contract_descriptor = create_contract_descriptor();
    let oracle_announcements = create_oracle_announcements();
    ContractInfo {
        contract_descriptor,
        oracle_announcements,
        threshold: THRESHOLD,
    }
}

fn create_txinputinfo_vec() -> Vec<TxInputInfo> {
    let tx_input_info = TxInputInfo {
        outpoint: OutPoint::default(),
        redeem_script: Script::new(),
        max_witness_len: 108,
        serial_id: 2,
    };
    vec![tx_input_info]
}

fn create_transactions(payouts: &[Payout]) -> DlcTransactions {
    let offer_params = PartyParams {
        fund_pubkey: secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &offer_seckey()),
        change_script_pubkey: get_p2wpkh_script_pubkey(),
        change_serial_id: 4,
        payout_script_pubkey: get_p2wpkh_script_pubkey(),
        payout_serial_id: 1,
        inputs: create_txinputinfo_vec(),
        input_amount: 300000000,
        collateral: TOTAL_COLLATERAL/2,
    };

    let accept_params = PartyParams {
        fund_pubkey: secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &accept_seckey()),
        change_script_pubkey: get_p2wpkh_script_pubkey(),
        change_serial_id: 4,
        payout_script_pubkey: get_p2wpkh_script_pubkey(),
        payout_serial_id: 1,
        inputs: create_txinputinfo_vec(),
        input_amount: 300000000,
        collateral: TOTAL_COLLATERAL/2,
    };
    create_dlc_transactions(&offer_params, &accept_params, payouts, 1000, 2, 0, 1000, 3).unwrap()
}

fn accept_seckey() -> SecretKey {
    "c0296e3059b34c9707f05dc54ec008de90c0ce52841ff54b98e51487de031e6d"
        .parse()
        .unwrap()
}

fn offer_seckey() -> SecretKey {
    "c3b1634c6a13019f372722db0ec0435df11fb2dd6b0b5c647503ef6b5e4656ec"
        .parse()
        .unwrap()
}

/// Benchmark to measure the adaptor signature creation time.
pub fn sign_bench(c: &mut Criterion) {
    let contract_info = create_contract_info();
    let dlc_transactions = create_transactions(&contract_info.get_payouts(200000000));
    let fund_output_value = dlc_transactions.get_fund_output().value;

    let seckey = accept_seckey();
    c.bench_function("sign", |b| {
        b.iter(|| {
            black_box(
                contract_info
                    .get_adaptor_info(
                        SECP256K1,
                        TOTAL_COLLATERAL,
                        &seckey,
                        &dlc_transactions.funding_script_pubkey,
                        fund_output_value,
                        &dlc_transactions.cets,
                        0,
                    )
                    .unwrap(),
            )
        });
    });
}

/// Benchmark to measure the adaptor signature verification time.
pub fn verify_bench(c: &mut Criterion) {
    let contract_info = create_contract_info();
    let dlc_transactions = create_transactions(&contract_info.get_payouts(200000000));
    let fund_output_value = dlc_transactions.get_fund_output().value;

    let seckey = accept_seckey();
    let pubkey = secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &seckey);
    let adaptor_info = contract_info
        .get_adaptor_info(
            SECP256K1,
            TOTAL_COLLATERAL,
            &seckey,
            &dlc_transactions.funding_script_pubkey,
            fund_output_value,
            &dlc_transactions.cets,
            0,
        )
        .unwrap();
    let adaptor_signatures = &adaptor_info.1;
    c.bench_function("verify", |b| {
        b.iter(|| {
            black_box(
                contract_info
                    .verify_adaptor_info(
                        SECP256K1,
                        &pubkey,
                        &dlc_transactions.funding_script_pubkey,
                        fund_output_value,
                        &dlc_transactions.cets,
                        adaptor_signatures,
                        0,
                        &adaptor_info.0,
                    )
                    .unwrap(),
            );
        });
    });
}

criterion_group! {
    name = sign_verify_bench;
    config = Criterion::default().sample_size(10);
    targets = sign_bench, verify_bench
}
criterion_main!(sign_verify_bench);
