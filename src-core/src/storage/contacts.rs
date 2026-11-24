//! Public contacts storage surface. See `storage::db` for implementations.
#![allow(unused_imports)]

pub use crate::storage::db::{
    accept_contact_request, add_contact, list_contacts, parse_invite_string,
    reject_contact_request, set_contact_trust,
};
