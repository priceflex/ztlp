//! System tray setup and event handling.
//!
//! Creates a tray icon with a context menu showing connection status,
//! connect/disconnect toggle, and app controls.

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager,
};

use crate::state::{AppState, ConnectionState};

/// Build the tray icon and register its event handlers.
pub fn setup_tray(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    // Build the context menu
    let status_item = MenuItem::with_id(app, "status", "○ Disconnected", false, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let connect_item = MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?;
    let disconnect_item =
        MenuItem::with_id(app, "disconnect", "Disconnect", false, None::<&str>)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let open_item = MenuItem::with_id(app, "open", "Open ZTLP", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &status_item,
            &sep1,
            &connect_item,
            &disconnect_item,
            &sep2,
            &open_item,
            &quit_item,
        ],
    )?;

    let _tray = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("ZTLP — Disconnected")
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "connect" => {
                let state = app.state::<AppState>();
                let config = state.config.lock().unwrap();
                let relay = config.relay_address.clone();
                let zone = "default".to_string();
                drop(config);

                let relay = if relay.is_empty() {
                    "relay.ztlp.net:4433".to_string()
                } else {
                    relay
                };

                if let Ok(status) = crate::tunnel::start_tunnel(&relay, &zone) {
                    *state.status.lock().unwrap() = status;
                    let _ = update_tray_menu(app);
                }
            }
            "disconnect" => {
                let state = app.state::<AppState>();
                if crate::tunnel::stop_tunnel().is_ok() {
                    *state.status.lock().unwrap() = Default::default();
                    let _ = update_tray_menu(app);
                }
            }
            "open" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}

/// Update the tray menu to reflect the current connection state.
pub fn update_tray_menu(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let state = app.state::<AppState>();
    let status = state.status.lock().unwrap();

    let (status_text, tooltip, connect_enabled, disconnect_enabled) = match status.state {
        ConnectionState::Connected => {
            let relay_display = if status.relay.is_empty() {
                "relay".to_string()
            } else {
                status.relay.clone()
            };
            (
                format!("● Connected to {}", relay_display),
                format!("ZTLP — Connected to {}", relay_display),
                false,
                true,
            )
        }
        ConnectionState::Connecting => (
            "◐ Connecting…".to_string(),
            "ZTLP — Connecting…".to_string(),
            false,
            false,
        ),
        ConnectionState::Reconnecting => (
            "◐ Reconnecting…".to_string(),
            "ZTLP — Reconnecting…".to_string(),
            false,
            true,
        ),
        ConnectionState::Disconnecting => (
            "◑ Disconnecting…".to_string(),
            "ZTLP — Disconnecting…".to_string(),
            false,
            false,
        ),
        ConnectionState::Disconnected => (
            "○ Disconnected".to_string(),
            "ZTLP — Disconnected".to_string(),
            true,
            false,
        ),
    };
    drop(status);

    // Rebuild the tray menu with updated state.
    // Tauri 2 tray menus are immutable once built; we rebuild the menu
    // each time the connection state changes.
    if let Some(tray) = app.tray_by_id("main") {
        let status_item =
            MenuItem::with_id(app, "status", &status_text, false, None::<&str>)?;
        let sep1 = PredefinedMenuItem::separator(app)?;
        let connect_item =
            MenuItem::with_id(app, "connect", "Connect", connect_enabled, None::<&str>)?;
        let disconnect_item =
            MenuItem::with_id(app, "disconnect", "Disconnect", disconnect_enabled, None::<&str>)?;
        let sep2 = PredefinedMenuItem::separator(app)?;
        let open_item = MenuItem::with_id(app, "open", "Open ZTLP", true, None::<&str>)?;
        let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

        let menu = Menu::with_items(
            app,
            &[
                &status_item,
                &sep1,
                &connect_item,
                &disconnect_item,
                &sep2,
                &open_item,
                &quit_item,
            ],
        )?;

        tray.set_menu(Some(menu))?;
        tray.set_tooltip(Some(&tooltip))?;
    }

    Ok(())
}
