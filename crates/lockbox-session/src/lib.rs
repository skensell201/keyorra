//! Desktop-app logic over `lockbox-core`, free of any UI framework so it can be unit-tested.

pub mod error;

pub use error::{CmdError, CmdResult, ErrorKind};
