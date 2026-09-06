//! Security-oriented core for `safeclone`.

pub mod cli;
pub mod content;
pub mod detection;
pub mod filename;
mod fs_boundary;
pub mod inventory;
mod locality;
pub mod path_evidence;
pub mod path_transform;
pub mod pipeline;
pub mod policy;
pub mod promotion;
pub mod roundtrip;
mod rule_metadata;
pub mod secrets;
pub mod sensitive;
pub mod staging;
pub mod staging_tree;
pub mod transform;
pub mod verification;

pub use locality::LocalityError;
