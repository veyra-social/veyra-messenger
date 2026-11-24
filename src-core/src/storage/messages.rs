//! Public messages storage surface. See `storage::db` for implementations.
#![allow(unused_imports)]

pub use crate::storage::db::{
    chat_member_multiaddrs, list_messages, mark_message_status, retry_message,
    save_inbound_message, save_outbound_message,
};
