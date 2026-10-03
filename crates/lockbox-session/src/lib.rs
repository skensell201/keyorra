//! Desktop-app logic over `lockbox-core`, free of any UI framework so it can be unit-tested.

pub mod autolock;
pub mod clipboard;
pub mod error;
pub mod session;
pub mod throttle;

pub use error::{CmdError, CmdResult, ErrorKind};
pub use session::{Session, Status};
