#[macro_use]
mod test_utils;

use bitcoin::Address;
use bitcoin_rpc_provider::BitcoinCoreProvider;
use bitcoin_test_utils::rpc_helpers::init_clients;
use bitcoincore_rpc::{Client, RpcApi};
use dlc_manager::contract::contract_input::ContractInput;
use dlc_manager::manager::Manager;
use dlc_manager::ChannelId;
use dlc_manager::{
    channel::{signed_channel::SignedChannelState, Channel},
    contract::Contract,
    Oracle, Storage,
};
use dlc_messages::Message;
use lightning::util::ser::Writeable;
use mocks::memory_storage_provider::MemoryStorage;
use mocks::mock_oracle_provider::MockOracle;
use mocks::mock_time::MockTime;
use secp256k1_zkp::rand::{thread_rng, RngCore};
use secp256k1_zkp::EcdsaAdaptorSignature;
use test_utils::{get_enum_test_params, TestParams};

use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::channel,
        Arc, Mutex,
    },
};

type DlcParty = Arc<
    Mutex<
        Manager<
            Arc<BitcoinCoreProvider>,
            Arc<BitcoinCoreProvider>,
            Box<MemoryStorage>,
            Arc<MockOracle>,
            Arc<MockTime>,
            Arc<BitcoinCoreProvider>,
        >,
    >,
>;

fn alter_adaptor_sig(input: &EcdsaAdaptorSignature) -> EcdsaAdaptorSignature {
    let mut copy = input.as_ref().to_vec();
    let i = thread_rng().next_u32() as usize % secp256k1_zkp::ffi::ECDSA_ADAPTOR_SIGNATURE_LENGTH;
    copy[i] = copy[i].checked_add(1).unwrap_or(0);
    EcdsaAdaptorSignature::from_slice(&copy).expect("to be able to create an adaptor signature")
}

#[derive(Eq, PartialEq, Clone)]
enum TestPath {
    Close,
    BadAcceptBufferAdaptorSignature,
    BadSignBufferAdaptorSignature,
    SettleClose,
    BufferCheat,
    RenewedClose,
    SettleCheat,
    CollaborativeClose,
    SettleRenewSettle,
    SettleOfferTimeout,
    SettleAcceptTimeout,
    SettleConfirmTimeout,
    SettleReject,
    SettleRace,
    RenewOfferTimeout,
    RenewAcceptTimeout,
    RenewConfirmTimeout,
    RenewReject,
    RenewRace,
}

#[test]
#[ignore]
fn channel_established_close_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::Close);
}

#[test]
#[ignore]
fn channel_bad_accept_buffer_adaptor_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::BadAcceptBufferAdaptorSignature,
    );
}

#[test]
#[ignore]
fn channel_bad_sign_buffer_adaptor_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::BadSignBufferAdaptorSignature,
    );
}

#[test]
#[ignore]
fn channel_settled_close_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::SettleClose);
}

#[test]
#[ignore]
fn channel_punish_buffer_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::BufferCheat);
}

#[test]
#[ignore]
fn channel_renew_close_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::RenewedClose);
}

#[test]
#[ignore]
fn channel_settle_cheat_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::SettleCheat);
}

#[test]
#[ignore]
fn channel_collaborative_close_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::CollaborativeClose,
    );
}

#[test]
#[ignore]
fn channel_settle_renew_settle_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::SettleRenewSettle,
    );
}

#[test]
#[ignore]
fn channel_settle_offer_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::SettleOfferTimeout,
    );
}

#[test]
#[ignore]
fn channel_settle_accept_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::SettleAcceptTimeout,
    );
}

#[test]
#[ignore]
fn channel_settle_confirm_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::SettleConfirmTimeout,
    );
}

#[test]
#[ignore]
fn channel_settle_reject_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::SettleReject);
}

#[test]
#[ignore]
fn channel_settle_race_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::SettleRace);
}

#[test]
#[ignore]
fn channel_renew_offer_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::RenewOfferTimeout,
    );
}

#[test]
#[ignore]
fn channel_renew_accept_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::RenewAcceptTimeout,
    );
}

#[test]
#[ignore]
fn channel_renew_confirm_timeout_test() {
    channel_execution_test(
        get_enum_test_params(1, 1, None),
        TestPath::RenewConfirmTimeout,
    );
}

#[test]
#[ignore]
fn channel_renew_reject_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::RenewReject);
}

#[test]
#[ignore]
fn channel_renew_race_test() {
    channel_execution_test(get_enum_test_params(1, 1, None), TestPath::RenewRace);
}

fn channel_execution_test(test_params: TestParams, path: TestPath) {
    env_logger::init();
    let (alice_send, bob_receive) = channel::<Option<Message>>();
    let (bob_send, alice_receive) = channel::<Option<Message>>();
    let (sync_send, sync_receive) = channel::<()>();
    let alice_sync_send = sync_send.clone();
    let bob_sync_send = sync_send;
    let (alice_rpc, bob_rpc, sink_rpc) = init_clients();

    let alice_bitcoin_core = Arc::new(BitcoinCoreProvider::new_from_rpc_client(alice_rpc));

    let bob_bitcoin_core = Arc::new(BitcoinCoreProvider::new_from_rpc_client(bob_rpc));

    let mut alice_oracles = HashMap::with_capacity(1);
    let mut bob_oracles = HashMap::with_capacity(1);

    for oracle in test_params.oracles {
        let oracle = Arc::new(oracle);
        alice_oracles.insert(oracle.get_public_key(), Arc::clone(&oracle));
        bob_oracles.insert(oracle.get_public_key(), Arc::clone(&oracle));
    }

    let alice_store = mocks::memory_storage_provider::MemoryStorage::new();
    let bob_store = mocks::memory_storage_provider::MemoryStorage::new();
    let mock_time = Arc::new(mocks::mock_time::MockTime {});
    mocks::mock_time::set_time((test_params.contract_input.maturity_time as u64) - 1);

    let alice_manager = Arc::new(Mutex::new(
        Manager::new(
            Arc::clone(&alice_bitcoin_core),
            Arc::clone(&alice_bitcoin_core),
            Box::new(alice_store),
            alice_oracles,
            Arc::clone(&mock_time),
            Arc::clone(&alice_bitcoin_core),
        )
        .unwrap(),
    ));

    let alice_manager_loop = Arc::clone(&alice_manager);
    let alice_manager_send = Arc::clone(&alice_manager);

    let bob_manager = Arc::new(Mutex::new(
        Manager::new(
            Arc::clone(&bob_bitcoin_core),
            Arc::clone(&bob_bitcoin_core),
            Box::new(bob_store),
            bob_oracles,
            Arc::clone(&mock_time),
            Arc::clone(&bob_bitcoin_core),
        )
        .unwrap(),
    ));

    let bob_manager_loop = Arc::clone(&bob_manager);
    let bob_manager_send = Arc::clone(&bob_manager);
    let alice_send_loop = alice_send.clone();
    let bob_send_loop = bob_send.clone();

    let alice_expect_error = Arc::new(AtomicBool::new(false));
    let bob_expect_error = Arc::new(AtomicBool::new(false));

    let alice_expect_error_loop = alice_expect_error.clone();
    let bob_expect_error_loop = bob_expect_error.clone();

    let path_copy = path.clone();
    let msg_filter = move |msg| {
        if let TestPath::SettleAcceptTimeout = path_copy {
            if let Message::SettleConfirm(_) = msg {
                return None;
            }
        }
        if let TestPath::SettleConfirmTimeout = path_copy {
            if let Message::SettleFinalize(_) = msg {
                return None;
            }
        }
        if let TestPath::RenewAcceptTimeout = path_copy {
            if let Message::RenewConfirm(_) = msg {
                return None;
            }
        }
        if let TestPath::RenewConfirmTimeout = path_copy {
            if let Message::RenewFinalize(_) = msg {
                return None;
            }
        }
        Some(msg)
    };

    let msg_filter_copy = msg_filter.clone();
    let path_copy = path.clone();
    let alter_sign = move |msg| match msg {
        Message::SignChannel(mut sign_channel) => {
            if path_copy == TestPath::BadSignBufferAdaptorSignature {
                sign_channel.buffer_adaptor_signature =
                    alter_adaptor_sig(&sign_channel.buffer_adaptor_signature);
            }
            Some(Message::SignChannel(sign_channel))
        }
        _ => msg_filter_copy(msg),
    };

    let alice_handle = receive_loop!(
        alice_receive,
        alice_manager_loop,
        alice_send_loop,
        alice_expect_error_loop,
        alice_sync_send,
        msg_filter,
        |msg| msg
    );

    let bob_handle = receive_loop!(
        bob_receive,
        bob_manager_loop,
        bob_send_loop,
        bob_expect_error_loop,
        bob_sync_send,
        alter_sign,
        |msg| msg
    );

    let offer_msg = bob_manager_send
        .lock()
        .unwrap()
        .offer_channel(
            &test_params.contract_input,
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
                .parse()
                .unwrap(),
        )
        .expect("Send offer error");

    let temporary_channel_id = offer_msg.temporary_channel_id;
    bob_send
        .send(Some(Message::OfferChannel(offer_msg)))
        .unwrap();

    assert_channel_state!(bob_manager_send, temporary_channel_id, Offered);

    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(alice_manager_send, temporary_channel_id, Offered);

    let (mut accept_msg, channel_id, contract_id, _) = alice_manager_send
        .lock()
        .unwrap()
        .accept_channel(&temporary_channel_id)
        .expect("Error accepting contract offer");
    assert_channel_state!(alice_manager_send, channel_id, Accepted);

    match path {
        TestPath::BadAcceptBufferAdaptorSignature => {
            accept_msg.buffer_adaptor_signature =
                alter_adaptor_sig(&accept_msg.buffer_adaptor_signature);
            bob_expect_error.store(true, Ordering::Relaxed);
            alice_send
                .send(Some(Message::AcceptChannel(accept_msg)))
                .unwrap();
            sync_receive.recv().expect("Error synchronizing");
            assert_channel_state!(bob_manager_send, temporary_channel_id, FailedAccept);
        }
        TestPath::BadSignBufferAdaptorSignature => {
            alice_expect_error.store(true, Ordering::Relaxed);
            alice_send
                .send(Some(Message::AcceptChannel(accept_msg)))
                .unwrap();
            // Bob receives accept message
            sync_receive.recv().expect("Error synchronizing");
            // Alice receives sign message
            sync_receive.recv().expect("Error synchronizing");
            assert_channel_state!(alice_manager_send, channel_id, FailedSign);
        }
        _ => {
            alice_send
                .send(Some(Message::AcceptChannel(accept_msg)))
                .unwrap();
            sync_receive.recv().expect("Error synchronizing");

            assert_channel_state!(bob_manager_send, channel_id, Signed, Established);

            sync_receive.recv().expect("Error synchronizing");

            assert_channel_state!(alice_manager_send, channel_id, Signed, Established);

            let sink_address = sink_rpc.get_new_address(None, None).expect("RPC Error");
            sink_rpc
                .generate_to_address(6, &sink_address)
                .expect("RPC Error");

            mocks::mock_time::set_time((test_params.contract_input.maturity_time as u64) + 1);

            alice_manager_send
                .lock()
                .unwrap()
                .periodic_check()
                .expect("to be able to do the periodic check");

            bob_manager_send
                .lock()
                .unwrap()
                .periodic_check()
                .expect("to be able to do the periodic check");

            assert_contract_state!(alice_manager_send, contract_id, Confirmed);
            assert_contract_state!(bob_manager_send, contract_id, Confirmed);

            // Select the first one to close or refund randomly
            let (first, first_send, second, second_send) = if thread_rng().next_u32() % 2 == 0 {
                (alice_manager_send, &alice_send, bob_manager_send, &bob_send)
            } else {
                (bob_manager_send, &bob_send, alice_manager_send, &alice_send)
            };

            match path {
                TestPath::Close => {
                    close_established_channel(first, second, channel_id, sink_rpc, sink_address);
                }
                TestPath::CollaborativeClose => {
                    collaborative_close(
                        first,
                        first_send,
                        second,
                        channel_id,
                        &sync_receive,
                        sink_rpc,
                        sink_address,
                    );
                }
                TestPath::SettleOfferTimeout
                | TestPath::SettleAcceptTimeout
                | TestPath::SettleConfirmTimeout => {
                    settle_timeout(
                        first,
                        first_send,
                        second,
                        second_send,
                        channel_id,
                        &sync_receive,
                        &test_params.contract_input,
                        path,
                    );
                }
                TestPath::SettleReject => {
                    settle_reject(
                        first,
                        first_send,
                        second,
                        second_send,
                        channel_id,
                        &sync_receive,
                    );
                }
                TestPath::SettleRace => {
                    settle_race(
                        first,
                        first_send,
                        second,
                        second_send,
                        channel_id,
                        &sync_receive,
                    );
                }
                _ => {
                    // Shuffle positions
                    let (first, first_send, second, second_send) =
                        if thread_rng().next_u32() % 2 == 0 {
                            (first, first_send, second, second_send)
                        } else {
                            (second, second_send, first, first_send)
                        };

                    first.lock().unwrap().get_mut_store().save();

                    settle_channel(
                        first.clone(),
                        first_send,
                        second.clone(),
                        second_send,
                        channel_id,
                        &sync_receive,
                    );

                    match path {
                        TestPath::SettleClose => {
                            let closer = if thread_rng().next_u32() % 2 == 0 {
                                first
                            } else {
                                second
                            };

                            closer
                                .lock()
                                .unwrap()
                                .force_close_channel(&channel_id)
                                .expect("to be able to unilaterally close the channel.");
                        }
                        TestPath::BufferCheat => {
                            cheat_punish(first, second, channel_id, sink_rpc, sink_address, true);
                        }
                        TestPath::RenewOfferTimeout
                        | TestPath::RenewAcceptTimeout
                        | TestPath::RenewConfirmTimeout => {
                            renew_timeout(
                                first,
                                first_send,
                                second,
                                second_send,
                                channel_id,
                                &sync_receive,
                                &test_params.contract_input,
                                path,
                            );
                        }
                        TestPath::RenewReject => {
                            renew_reject(
                                first,
                                first_send,
                                second,
                                second_send,
                                channel_id,
                                &sync_receive,
                                &test_params.contract_input,
                            );
                        }
                        TestPath::RenewRace => {
                            renew_race(
                                first,
                                first_send,
                                second,
                                second_send,
                                channel_id,
                                &sync_receive,
                                &test_params.contract_input,
                            );
                        }
                        TestPath::RenewedClose | TestPath::SettleCheat => {
                            first.lock().unwrap().get_mut_store().save();

                            renew_channel(
                                first.clone(),
                                first_send,
                                second.clone(),
                                second_send,
                                channel_id,
                                &sync_receive,
                                &test_params.contract_input,
                            );

                            if let TestPath::RenewedClose = path {
                                close_established_channel(
                                    first,
                                    second,
                                    channel_id,
                                    sink_rpc,
                                    sink_address,
                                );
                            } else if let TestPath::SettleCheat = path {
                                cheat_punish(
                                    first,
                                    second,
                                    channel_id,
                                    sink_rpc,
                                    sink_address,
                                    false,
                                );
                            }
                        }
                        TestPath::SettleRenewSettle => {
                            renew_channel(
                                first.clone(),
                                first_send,
                                second.clone(),
                                second_send,
                                channel_id,
                                &sync_receive,
                                &test_params.contract_input,
                            );

                            settle_channel(
                                first,
                                first_send,
                                second,
                                second_send,
                                channel_id,
                                &sync_receive,
                            );
                        }
                        _ => (),
                    }
                }
            }
        }
    }

    alice_send.send(None).unwrap();
    bob_send.send(None).unwrap();

    alice_handle.join().unwrap();
    bob_handle.join().unwrap();
}

fn close_established_channel(
    first: DlcParty,
    second: DlcParty,
    channel_id: ChannelId,
    sink_rpc: Client,
    sink_address: Address,
) {
    first
        .lock()
        .unwrap()
        .force_close_channel(&channel_id)
        .expect("to be able to unilaterally close.");
    assert_channel_state!(first, channel_id, Signed, Closing);

    first
        .lock()
        .unwrap()
        .periodic_check()
        .expect("to be able to do the periodic check");

    let wait = dlc_manager::manager::CET_NSEQUENCE;

    sink_rpc
        .generate_to_address(10, &sink_address)
        .expect("RPC Error");

    first
        .lock()
        .unwrap()
        .periodic_check()
        .expect("to be able to do the periodic check");

    // Should not have changed state before the CET is spendable.
    assert_channel_state!(first, channel_id, Signed, Closing);

    sink_rpc
        .generate_to_address(wait as u64 - 9, &sink_address)
        .expect("RPC Error");

    first
        .lock()
        .unwrap()
        .periodic_check()
        .expect("to be able to do the periodic check");

    //
    assert_channel_state!(first, channel_id, Signed, Closed);

    second
        .lock()
        .unwrap()
        .periodic_check()
        .expect("to be able to do the periodic check");

    assert_channel_state!(second, channel_id, Signed, CounterClosed);
}

fn cheat_punish(
    first: DlcParty,
    second: DlcParty,
    channel_id: ChannelId,
    sink_rpc: Client,
    sink_address: Address,
    established: bool,
) {
    first.lock().unwrap().get_mut_store().rollback();

    if established {
        first
            .lock()
            .unwrap()
            .force_close_channel(&channel_id)
            .expect("the cheater to be able to close on established");
    } else {
        first
            .lock()
            .unwrap()
            .force_close_channel(&channel_id)
            .expect("the cheater to be able to close on settled");
    }

    sink_rpc
        .generate_to_address(2, &sink_address)
        .expect("RPC Error");

    second
        .lock()
        .unwrap()
        .periodic_check()
        .expect("the check to succeed");

    assert_channel_state!(second, channel_id, Signed, ClosedPunished);
}

fn settle_channel(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    channel_id: ChannelId,
    sync_receive: &Receiver<()>,
) {
    let (settle_offer, _) = first
        .lock()
        .unwrap()
        .settle_offer(&channel_id, 100000000)
        .expect("to be able to offer a settlement of the contract.");

    first_send
        .send(Some(Message::SettleOffer(settle_offer)))
        .unwrap();

    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, SettledOffered);

    assert_channel_state!(second, channel_id, Signed, SettledReceived);

    let (settle_accept, _) = second
        .lock()
        .unwrap()
        .accept_settle_offer(&channel_id)
        .expect("to be able to accept a settlement offer");

    second_send
        .send(Some(Message::SettleAccept(settle_accept)))
        .unwrap();

    // Process Accept
    sync_receive.recv().expect("Error synchronizing");
    // Process Confirm
    sync_receive.recv().expect("Error synchronizing");
    // Process Finalize
    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, Settled);

    assert_channel_state!(second, channel_id, Signed, Settled);
}

fn settle_reject(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    channel_id: ChannelId,
    sync_receive: &Receiver<()>,
) {
    let (settle_offer, _) = first
        .lock()
        .unwrap()
        .settle_offer(&channel_id, 100000000)
        .expect("to be able to reject a settlement of the contract.");

    first_send
        .send(Some(Message::SettleOffer(settle_offer)))
        .unwrap();

    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, SettledOffered);

    assert_channel_state!(second, channel_id, Signed, SettledReceived);

    let (settle_reject, _) = second
        .lock()
        .unwrap()
        .reject_settle_offer(&channel_id)
        .expect("to be able to reject a settlement offer");

    second_send
        .send(Some(Message::Reject(settle_reject)))
        .unwrap();

    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, Established);

    assert_channel_state!(second, channel_id, Signed, Established);
}

fn settle_race(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    channel_id: ChannelId,
    sync_receive: &Receiver<()>,
) {
    let (settle_offer, _) = first
        .lock()
        .unwrap()
        .settle_offer(&channel_id, 100000000)
        .expect("to be able to offer a settlement of the contract.");

    let (settle_offer_2, _) = second
        .lock()
        .unwrap()
        .settle_offer(&channel_id, 100000000)
        .expect("to be able to offer a settlement of the contract.");

    first_send
        .send(Some(Message::SettleOffer(settle_offer)))
        .unwrap();

    second_send
        .send(Some(Message::SettleOffer(settle_offer_2)))
        .unwrap();

    // Process 2 offers + 2 rejects
    sync_receive.recv().expect("Error synchronizing");
    sync_receive.recv().expect("Error synchronizing");
    sync_receive.recv().expect("Error synchronizing");
    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, Established);

    assert_channel_state!(second, channel_id, Signed, Established);
}

fn renew_channel(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    channel_id: ChannelId,
    sync_receive: &Receiver<()>,
    contract_input: &ContractInput,
) {
    let (renew_offer, _) = first
        .lock()
        .unwrap()
        .renew_offer(&channel_id, 100000000, contract_input)
        .expect("to be able to renew channel contract");

    first_send
        .send(Some(Message::RenewOffer(renew_offer)))
        .expect("to be able to send the renew offer");

    // Process Renew Offer
    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, RenewOffered);
    assert_channel_state!(second, channel_id, Signed, RenewOffered);

    let (accept_renew, _) = second
        .lock()
        .unwrap()
        .accept_renew_offer(&channel_id)
        .expect("to be able to accept the renewal");

    second_send
        .send(Some(Message::RenewAccept(accept_renew)))
        .expect("to be able to send the accept renew");

    // Process Renew Accept
    sync_receive.recv().expect("Error synchronizing");
    assert_channel_state!(first, channel_id, Signed, RenewConfirmed);
    // Process Renew Confirm
    sync_receive.recv().expect("Error synchronizing");
    // Process Renew Finalize
    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, Established);
    assert_channel_state!(second, channel_id, Signed, Established);
}

fn renew_reject(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    channel_id: ChannelId,
    sync_receive: &Receiver<()>,
    contract_input: &ContractInput,
) {
    let (renew_offer, _) = first
        .lock()
        .unwrap()
        .renew_offer(&channel_id, 100000000, contract_input)
        .expect("to be able to renew channel contract");

    first_send
        .send(Some(Message::RenewOffer(renew_offer)))
        .expect("to be able to send the renew offer");

    // Process Renew Offer
    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, RenewOffered);
    assert_channel_state!(second, channel_id, Signed, RenewOffered);

    let (renew_reject, _) = second
        .lock()
        .unwrap()
        .reject_renew_offer(&channel_id)
        .expect("to be able to reject the renewal");

    second_send
        .send(Some(Message::Reject(renew_reject)))
        .expect("to be able to send the renew reject");

    // Process Renew Reject
    sync_receive.recv().expect("Error synchronizing");
    assert_channel_state!(first, channel_id, Signed, Settled);
    assert_channel_state!(second, channel_id, Signed, Settled);
}

fn renew_race(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    channel_id: ChannelId,
    sync_receive: &Receiver<()>,
    contract_input: &ContractInput,
) {
    let (renew_offer, _) = first
        .lock()
        .unwrap()
        .renew_offer(&channel_id, 100000000, contract_input)
        .expect("to be able to renew channel contract");

    let (renew_offer_2, _) = second
        .lock()
        .unwrap()
        .renew_offer(&channel_id, 100000000, contract_input)
        .expect("to be able to renew channel contract");

    first_send
        .send(Some(Message::RenewOffer(renew_offer)))
        .expect("to be able to send the renew offer");

    second_send
        .send(Some(Message::RenewOffer(renew_offer_2)))
        .expect("to be able to send the renew offer");

    // Process 2 offers + 2 rejects
    sync_receive.recv().expect("Error synchronizing");
    sync_receive.recv().expect("Error synchronizing");
    sync_receive.recv().expect("Error synchronizing");
    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, Settled);
    assert_channel_state!(second, channel_id, Signed, Settled);
}

fn collaborative_close(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    second: DlcParty,
    channel_id: ChannelId,
    sync_receive: &Receiver<()>,
    sink_rpc: Client,
    sink_address: Address,
) {
    let close_offer = first
        .lock()
        .unwrap()
        .offer_collaborative_close(&channel_id, 100000000)
        .expect("to be able to propose a collaborative close");
    first_send
        .send(Some(Message::CollaborativeCloseOffer(close_offer)))
        .expect("to be able to send collaborative close");
    sync_receive.recv().expect("Error synchronizing");

    assert_channel_state!(first, channel_id, Signed, CollaborativeCloseOffered);
    assert_channel_state!(second, channel_id, Signed, CollaborativeCloseOffered);

    second
        .lock()
        .unwrap()
        .accept_collaborative_close(&channel_id)
        .expect("to be able to accept a collaborative close");

    assert_channel_state!(second, channel_id, Signed, CollaborativelyClosed);

    sink_rpc
        .generate_to_address(2, &sink_address)
        .expect("RPC Error");

    first
        .lock()
        .unwrap()
        .periodic_check()
        .expect("the check to succeed");

    assert_channel_state!(first, channel_id, Signed, CollaborativelyClosed);
}

fn renew_timeout(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    channel_id: ChannelId,
    sync_receive: &Receiver<()>,
    contract_input: &ContractInput,
    path: TestPath,
) {
    {
        let (renew_offer, _) = first
            .lock()
            .unwrap()
            .renew_offer(&channel_id, 100000000, contract_input)
            .expect("to be able to offer a settlement of the contract.");

        first_send
            .send(Some(Message::RenewOffer(renew_offer)))
            .unwrap();

        sync_receive.recv().expect("Error synchronizing");

        if let TestPath::RenewOfferTimeout = path {
            mocks::mock_time::set_time(
                (contract_input.maturity_time as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
            );
            first
                .lock()
                .unwrap()
                .periodic_check()
                .expect("not to error");

            assert_channel_state!(first, channel_id, Signed, Closed);
        } else {
            let (renew_accept, _) = second
                .lock()
                .unwrap()
                .accept_renew_offer(&channel_id)
                .expect("to be able to accept a settlement offer");

            second_send
                .send(Some(Message::RenewAccept(renew_accept)))
                .unwrap();

            // Process Accept
            sync_receive.recv().expect("Error synchronizing");

            if let TestPath::RenewAcceptTimeout = path {
                mocks::mock_time::set_time(
                    (contract_input.maturity_time as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
                );
                second
                    .lock()
                    .unwrap()
                    .periodic_check()
                    .expect("not to error");

                assert_channel_state!(second, channel_id, Signed, Closed);
            } else if let TestPath::RenewConfirmTimeout = path {
                // Process Confirm
                sync_receive.recv().expect("Error synchronizing");
                mocks::mock_time::set_time(
                    (contract_input.maturity_time as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
                );
                first
                    .lock()
                    .unwrap()
                    .periodic_check()
                    .expect("not to error");

                assert_channel_state!(first, channel_id, Signed, Closed);
            }
        }
    }
}

fn settle_timeout(
    first: DlcParty,
    first_send: &Sender<Option<Message>>,
    second: DlcParty,
    second_send: &Sender<Option<Message>>,
    channel_id: ChannelId,
    sync_receive: &Receiver<()>,
    contract_input: &ContractInput,
    path: TestPath,
) {
    let (settle_offer, _) = first
        .lock()
        .unwrap()
        .settle_offer(&channel_id, 100000000)
        .expect("to be able to offer a settlement of the contract.");

    first_send
        .send(Some(Message::SettleOffer(settle_offer)))
        .unwrap();

    sync_receive.recv().expect("Error synchronizing");

    if let TestPath::SettleOfferTimeout = path {
        mocks::mock_time::set_time(
            (contract_input.maturity_time as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
        );
        first
            .lock()
            .unwrap()
            .periodic_check()
            .expect("not to error");

        assert_channel_state!(first, channel_id, Signed, Closing);
    } else {
        let (settle_accept, _) = second
            .lock()
            .unwrap()
            .accept_settle_offer(&channel_id)
            .expect("to be able to accept a settlement offer");

        second_send
            .send(Some(Message::SettleAccept(settle_accept)))
            .unwrap();

        // Process Accept
        sync_receive.recv().expect("Error synchronizing");

        if let TestPath::SettleAcceptTimeout = path {
            mocks::mock_time::set_time(
                (contract_input.maturity_time as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
            );
            second
                .lock()
                .unwrap()
                .periodic_check()
                .expect("not to error");

            assert_channel_state!(second, channel_id, Signed, Closing);
        } else if let TestPath::SettleConfirmTimeout = path {
            // Process Confirm
            sync_receive.recv().expect("Error synchronizing");
            mocks::mock_time::set_time(
                (contract_input.maturity_time as u64) + dlc_manager::manager::PEER_TIMEOUT + 2,
            );
            first
                .lock()
                .unwrap()
                .periodic_check()
                .expect("not to error");

            assert_channel_state!(first, channel_id, Signed, Closing);
        }
    }
}
