// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod ipc;
mod setup;
mod state;
mod tray;
mod tunnel;

use state::AppState;
use tauri::{Manager, WebviewWindowBuilder};

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .setup(|app| {
            // Ensure the main window is VISIBLE on launch.
            //
            // The window is declared in tauri.conf.json (label "main") but the
            // shipped entrypoint never showed it, so the build was a tray-only
            // shell with no GUI. Two cases:
            //   (a) Tauri auto-created the config window but left it hidden
            //       -> just show + focus it.
            //   (b) It was never created -> build it, then show + focus.
            match app.get_webview_window("main") {
                Some(existing) => {
                    let _ = existing.show();
                    let _ = existing.set_focus();
                    let _ = existing.set_always_on_top(false);
                }
                None => {
                    let window = WebviewWindowBuilder::new(
                        app,
                        "main",
                        tauri::WebviewUrl::App("index.html".into()),
                    )
                    .title("ZTLP")
                    .inner_size(900.0, 700.0)
                    .min_inner_size(720.0, 500.0)
                    .center()
                    .resizable(true)
                    .visible(true)
                    .build()?;
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            tray::setup_tray(app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::disconnect,
            commands::get_status,
            commands::get_identity,
            commands::get_attached,
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
            setup::setup_create_identity,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ZTLP desktop application");
}
