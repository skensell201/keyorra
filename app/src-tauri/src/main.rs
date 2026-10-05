// Prevents an extra console window on Windows in release; harmless on macOS.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Started by a browser for the extension: act as the native-messaging pipe, not the app.
    let args: Vec<String> = std::env::args().collect();
    if keyorra_session::bridge::host::is_host_launch(&args) {
        std::process::exit(keyorra_app_lib::native_host::run());
    }
    keyorra_app_lib::run()
}
