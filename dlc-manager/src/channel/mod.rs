//! #

use dlc_messages::channel::{AcceptChannel, SignChannel};

use crate::ChannelId;

use self::{
    accepted_channel::AcceptedChannel, offered_channel::OfferedChannel,
    signed_channel::SignedChannel,
};

pub mod accepted_channel;
pub mod offered_channel;
pub mod party_points;
pub mod ser;
pub mod signed_channel;
pub(crate) mod utils;

///
#[derive(Clone)]
pub enum Channel {
    ///
    Offered(OfferedChannel),
    ///
    Accepted(AcceptedChannel),
    ///
    Signed(SignedChannel),
    ///
    FailedAccept(FailedAccept),
    ///
    FailedSign(FailedSign),
}

// pub(crate) enum ChannelError {
//     Close(String),
//     Ignore(String),
// }

///
#[derive(Clone)]
pub struct FailedAccept {
    ///
    pub temporary_channel_id: ChannelId,
    ///
    pub error_message: String,
    ///
    pub accept_message: AcceptChannel,
}

///
#[derive(Clone)]
pub struct FailedSign {
    ///
    pub channel_id: ChannelId,
    ///
    pub error_message: String,
    ///
    pub sign_message: SignChannel,
}

impl Channel {
    ///
    pub fn get_temporary_id(&self) -> ChannelId {
        match self {
            Channel::Offered(o) => o.temporary_channel_id,
            Channel::Accepted(a) => a.temporary_channel_id,
            Channel::Signed(s) => s.temporary_channel_id,
            Channel::FailedAccept(f) => f.temporary_channel_id,
            _ => unimplemented!(),
        }
    }

    ///
    pub fn get_id(&self) -> ChannelId {
        match self {
            Channel::Offered(o) => o.temporary_channel_id,
            Channel::Accepted(a) => a.channel_id,
            Channel::Signed(s) => s.channel_id,
            Channel::FailedAccept(f) => f.temporary_channel_id,
            Channel::FailedSign(f) => f.channel_id,
        }
    }
}
