// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
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
            commands::get_services,
            commands::get_config,
            commands::save_config,
            commands::get_traffic_stats,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ZTLP desktop application");
}
