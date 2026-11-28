//! Process-wide override for the directory that owns `.ztlp/` state.
//!
//! Everything the agent keeps (identity, configs, CA, pins, caches, log)
//! normally lives in `~/.ztlp`. A host that has no usable home directory
//! (the iOS app and its Network Extension share an App Group container)
//! calls [`set_override`] once at start-up; from then on every `.ztlp`
//! lookup resolves under that directory instead. This is the explicit
//! equivalent of the macOS LaunchDaemon pinning `HOME` and the Windows
//! service setting `ZTLP_HOME`, without mutating the process environment
//! (unsafe once other threads exist).
//!
//! With no override set, nothing changes for any existing caller.

use std::path::PathBuf;

#[cfg(not(test))]
static OVERRIDE: std::sync::RwLock<Option<PathBuf>> = std::sync::RwLock::new(None);

// Unit tests run in parallel threads of one process and many of them
// resolve `~/.ztlp` paths; a process-wide override set by one test would
// redirect all the others. In test builds the override is per-thread
// (threads that must share it call `set_override` themselves).
#[cfg(test)]
thread_local! {
    static OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Install (`Some`) or clear (`None`) the state-home override.
pub fn set_override(dir: Option<PathBuf>) {
    #[cfg(not(test))]
    {
        if let Ok(mut g) = OVERRIDE.write() {
            *g = dir;
        }
    }
    #[cfg(test)]
    OVERRIDE.with(|o| *o.borrow_mut() = dir);
}

/// The override, if one is installed. The returned directory is the PARENT
/// of `.ztlp` (it plays the role of the home directory).
pub fn override_dir() -> Option<PathBuf> {
    #[cfg(not(test))]
    {
        OVERRIDE.read().ok().and_then(|g| g.clone())
    }
    #[cfg(test)]
    OVERRIDE.with(|o| o.borrow().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_round_trip() {
        assert_eq!(override_dir(), None);
        set_override(Some(PathBuf::from("/tmp/ztlp-state-home-test")));
        assert_eq!(
            override_dir(),
            Some(PathBuf::from("/tmp/ztlp-state-home-test"))
        );
        set_override(None);
        assert_eq!(override_dir(), None);
    }
}
