use std::collections::{HashMap, VecDeque};

use bitcoin::{Block, BlockHash, Transaction, Txid};
use secp256k1_zkp::EcdsaAdaptorSignature;

use crate::ChannelId;

const NB_SAVED_BLOCK_HASHES: usize = 6;

pub(crate) struct ChainMonitor {
    watched_tx: HashMap<Txid, ChannelInfo>,
    pub(crate) last_height: u64,
    pub(crate) last_block_hashes: VecDeque<BlockHash>,
}

#[derive(Clone, Debug)]
pub(crate) struct ChannelInfo {
    pub channel_id: ChannelId,
    pub tx_type: TxType,
}

#[derive(Clone, Debug)]
pub(crate) enum TxType {
    RevokedTx {
        update_idx: u64,
        own_adaptor_signature: EcdsaAdaptorSignature,
        is_offer: bool,
        revoked_tx_type: RevokedTxType,
    },
    CurTx,
    CollaborativeCloseTx,
}

#[derive(Clone, Debug)]
pub(crate) enum RevokedTxType {
    Buffer,
    Settle,
}

impl ChainMonitor {
    pub(crate) fn new(init_height: u64) -> Self {
        ChainMonitor {
            watched_tx: HashMap::new(),
            last_height: init_height,
            last_block_hashes: VecDeque::with_capacity(NB_SAVED_BLOCK_HASHES),
        }
    }

    pub(crate) fn add_tx(&mut self, txid: Txid, channel_info: ChannelInfo) {
        self.watched_tx.insert(txid, channel_info);
    }

    pub(crate) fn remove_tx(&mut self, txid: &Txid) {
        self.watched_tx.remove(txid);
    }

    pub(crate) fn process_block(
        &self,
        block: &Block,
        height: u64,
    ) -> Vec<(Transaction, ChannelInfo)> {
        let mut res = Vec::new();

        assert_eq!(self.last_height + 1, height);

        for tx in &block.txdata {
            let txid = tx.txid();
            if self.watched_tx.contains_key(&txid) {
                let channel_info = self
                    .watched_tx
                    .get(&txid)
                    .expect("to be able to retrieve the channel info");
                res.push((tx.clone(), channel_info.clone()));
            }
        }

        res
    }

    /// To be safe this is a separate function from process block to make sure updates are
    /// saved before we update the state. It is better to re-process a block than not
    /// process it at all.
    pub(crate) fn increment_height(&mut self, last_block_hash: BlockHash) {
        self.last_height += 1;
        self.last_block_hashes.push_back(last_block_hash.clone());
        if self.last_block_hashes.len() > NB_SAVED_BLOCK_HASHES {
            self.last_block_hashes.pop_front();
        }
    }
}
