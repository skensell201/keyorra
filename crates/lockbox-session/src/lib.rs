//! Desktop-app logic over `lockbox-core`, free of any UI framework so it can be unit-tested.

pub mod autolock;
pub mod error;
pub mod throttle;

pub use error::{CmdError, CmdResult, ErrorKind};
