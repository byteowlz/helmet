//! Tests for XDG-compliant path resolution

use helmet_core::APP_NAME;
use helmet_core::paths::{
    AppPaths, default_cache_dir, default_config_dir, default_data_dir, default_state_dir,
    expand_str_path, write_default_config,
};

// ============================================================================
// Path expansion
// ============================================================================

#[test]
fn expand_tilde_path() {
    let result = expand_str_path("~/test");
    assert!(result.is_ok());
    let path = result.expect("expand");
    // Should NOT start with ~
    assert!(!path.to_str().unwrap_or("").starts_with('~'));
}

#[test]
fn expand_plain_path_unchanged() {
    let result = expand_str_path("/tmp/test");
    assert!(result.is_ok());
    let path = result.expect("expand");
    assert_eq!(path.to_str().expect("str"), "/tmp/test");
}

// ============================================================================
// Default directories
// ============================================================================

#[test]
fn default_config_dir_contains_app_name() {
    let dir = default_config_dir();
    assert!(dir.is_ok());
    let path = dir.expect("config dir");
    assert!(
        path.to_str().unwrap_or("").contains(APP_NAME),
        "Config dir {} should contain app name",
        path.display()
    );
}

#[test]
fn default_data_dir_contains_app_name() {
    let dir = default_data_dir();
    assert!(dir.is_ok());
    let path = dir.expect("data dir");
    assert!(
        path.to_str().unwrap_or("").contains(APP_NAME),
        "Data dir {} should contain app name",
        path.display()
    );
}

#[test]
fn default_state_dir_contains_app_name() {
    let dir = default_state_dir();
    assert!(dir.is_ok());
    let path = dir.expect("state dir");
    assert!(
        path.to_str().unwrap_or("").contains(APP_NAME),
        "State dir {} should contain app name",
        path.display()
    );
}

#[test]
fn default_cache_dir_contains_app_name() {
    let dir = default_cache_dir();
    assert!(dir.is_ok());
    let path = dir.expect("cache dir");
    assert!(
        path.to_str().unwrap_or("").contains(APP_NAME),
        "Cache dir {} should contain app name",
        path.display()
    );
}

// ============================================================================
// XDG_CONFIG_HOME override
// ============================================================================

#[test]
fn xdg_config_home_respected() {
    // Save and restore env var
    let original = std::env::var("XDG_CONFIG_HOME").ok();

    // SAFETY: This test is single-threaded and we restore the original value.
    unsafe { std::env::set_var("XDG_CONFIG_HOME", "/tmp/test_xdg_config") };
    let dir = default_config_dir().expect("config dir");
    assert_eq!(
        dir.to_str().expect("str"),
        format!("/tmp/test_xdg_config/{}", APP_NAME)
    );

    // Restore
    // SAFETY: Restoring original environment state.
    match original {
        Some(val) => unsafe { std::env::set_var("XDG_CONFIG_HOME", val) },
        None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
    }
}

// ============================================================================
// AppPaths discovery
// ============================================================================

#[test]
fn discover_with_override_path() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config_path = dir.path().join("config.toml");

    let paths = AppPaths::discover(Some(config_path.clone()));
    assert!(paths.is_ok());
    let paths = paths.expect("discover");
    assert_eq!(paths.config_file, config_path);
}

#[test]
fn discover_with_directory_override() {
    let dir = tempfile::tempdir().expect("temp dir");

    let paths = AppPaths::discover(Some(dir.path().to_path_buf()));
    assert!(paths.is_ok());
    let paths = paths.expect("discover");
    // When given a directory, should append config.toml
    assert!(
        paths.config_file.ends_with("config.toml"),
        "Expected config.toml, got {}",
        paths.config_file.display()
    );
}

#[test]
fn discover_without_override_uses_defaults() {
    let paths = AppPaths::discover(None);
    assert!(paths.is_ok());
    let paths = paths.expect("discover");
    assert!(
        paths.config_file.to_str().unwrap_or("").contains(APP_NAME),
        "Default config path should contain app name"
    );
}

#[test]
fn app_paths_display() {
    let paths = AppPaths::discover(None).expect("discover");
    let display = format!("{}", paths);
    assert!(display.contains("config:"));
    assert!(display.contains("data:"));
    assert!(display.contains("state:"));
}

// ============================================================================
// write_default_config
// ============================================================================

#[test]
fn write_default_config_creates_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config_path = dir.path().join("subdir").join("config.toml");

    let result = write_default_config(&config_path);
    assert!(
        result.is_ok(),
        "write_default_config failed: {:?}",
        result.err()
    );
    assert!(config_path.exists(), "Config file should be created");

    let content = std::fs::read_to_string(&config_path).expect("read config");
    assert!(content.contains(APP_NAME), "Config should mention app name");
    assert!(
        content.contains("profile"),
        "Config should have profile field"
    );
}

#[test]
fn write_default_config_creates_parent_dirs() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config_path = dir.path().join("deep").join("nested").join("config.toml");

    let result = write_default_config(&config_path);
    assert!(result.is_ok());
    assert!(config_path.exists());
}

// ============================================================================
// ensure_directories
// ============================================================================

#[test]
fn ensure_directories_creates_dirs() {
    let dir = tempfile::tempdir().expect("temp dir");
    let paths = AppPaths {
        config_file: dir.path().join("config.toml"),
        data_dir: dir.path().join("data"),
        state_dir: dir.path().join("state"),
    };

    let result = paths.ensure_directories();
    assert!(result.is_ok());
    assert!(paths.data_dir.exists());
    assert!(paths.state_dir.exists());
}
