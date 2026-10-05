//! Desktop-app logic over `keyorra-core`, free of any UI framework so it can be unit-tested.

pub mod autolock;
pub mod bridge;
pub mod clipboard;
pub mod dto;
pub mod error;
pub mod session;
pub mod settings;
pub mod sleep;
pub mod sync;
pub mod throttle;
pub mod touchid;
pub mod watchtower;

pub use error::{CmdError, CmdResult, ErrorKind};
pub use session::{BridgeEvent, PairedBrowser, PairingRequest, QuickCopy, Session, Status};
pub use settings::Settings;
