//! Public bootstrap-node storage surface. The implementations live in
//! `storage::db`; this module documents the intended import path per the
//! project file map.
#![allow(unused_imports)]

pub use crate::storage::db::{
    add_bootstrap_node, list_bootstrap_nodes, mark_bootstrap_node_failure,
    mark_bootstrap_node_success, remove_bootstrap_node,
};
