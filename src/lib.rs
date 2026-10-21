//! PS4 save / PFS key management and crypto primitives.
//!
//! Ported from flatz's pkg_pfs_tool (keymgr + crypto + sealed-key / SD paths).

pub mod config;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod pfs;
pub mod settings;
pub mod sfo;

#[cfg(any(feature = "cli", feature = "gui", feature = "python", feature = "ios"))]
pub mod commands;

#[cfg(feature = "python")]
mod py;

pub use error::{Error, Result};
pub use keys::{CommonKeys, TitleKeyset};
