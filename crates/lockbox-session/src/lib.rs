//! Desktop-app logic over `lockbox-core`, free of any UI framework so it can be unit-tested.

pub mod autolock;
pub mod bridge;
pub mod clipboard;
pub mod dto;
pub mod error;
pub mod session;
pub mod settings;
pub mod sleep;
pub mod throttle;

pub use error::{CmdError, CmdResult, ErrorKind};
pub use session::{Session, Status};
pub use settings::Settings;
