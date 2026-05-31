// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod ipc;
mod setup;
mod state;
mod tray;
mod tunnel;

use state::AppState;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .setup(|app| {
            tray::setup_tray(app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::disconnect,
            commands::get_status,
            commands::get_identity,
            commands::enroll,
            commands::record_attestation,
            commands::get_services,
            commands::get_config,
            commands::save_config,
            commands::get_traffic_stats,
            setup::setup_status,
            setup::setup_run_ca_init,
            setup::setup_install_ca,
            setup::setup_install_dns,
            setup::setup_test_browse,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ZTLP desktop application");
}
