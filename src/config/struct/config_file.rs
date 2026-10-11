use serde::{Deserialize, Serialize};

use super::{DockEdgeSer, OutputHighlightRule, QuickCommand, Secret, Session};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WslProfile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub distribution: String,
    #[serde(default = "default_wsl_home")]
    pub directory: String,
}

fn default_wsl_home() -> String {
    "~".to_string()
}

// Testing-stage MCP defaults. Switch these serde defaults to false before the
// feature is promoted from preview to a stable release.
fn default_mcp_preview_enabled() -> bool {
    true
}

/// Ships with the "幻想 3048" sci-fi wallpaper on by default (a dark theme). New
/// installs and users upgrading from before the wallpaper feature get it; once
/// the user picks anything (including "无"/none, stored as ""), their choice is
/// saved and sticks.
fn default_wallpaper() -> String {
    // Serde default for the `wallpaper` field: kept at the old "幻想 3048" so an
    // *existing* config that predates the field stays on tech — `migrate_defaults`
    // then advances default-following users through the migration chain. Brand-new
    // installs get the current default straight from `fresh_config`.
    "builtin:tech".to_string()
}

/// Bump when `migrate_defaults` gains a new one-time default-layout change.
pub const DEFAULTS_REV: u32 = 3;

pub(crate) const PREVIOUS_DEFAULT_WALLPAPER_TRANSPARENCY: f32 = 0.38;
pub(crate) const PREVIOUS_DEFAULT_WALLPAPER_OVERLAY: f32 =
    1.0 - PREVIOUS_DEFAULT_WALLPAPER_TRANSPARENCY;
pub(crate) const DEFAULT_WALLPAPER_TRANSPARENCY: f32 = 0.15;
pub(crate) const DEFAULT_WALLPAPER_OVERLAY: f32 = 1.0 - DEFAULT_WALLPAPER_TRANSPARENCY;

pub(crate) fn default_sidebar_width() -> f32 {
    220.0
}
pub(crate) fn default_sidebar_height() -> f32 {
    240.0
}
pub(crate) fn default_sftp_width() -> f32 {
    380.0
}
pub(crate) fn default_sftp_height() -> f32 {
    220.0
}
pub(crate) fn default_sftp_tree_width() -> f32 {
    160.0
}

pub(crate) fn default_sftp_visible_columns() -> Vec<String> {
    ["name", "type", "size", "modified", "permissions", "owner", "group"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

pub(crate) fn default_quick_panel_width() -> f32 {
    260.0
}

pub(crate) fn default_quick_panel_height() -> f32 {
    220.0
}

/// HTTP MCP admission limits. Zero means unlimited; changes apply on restart.
/// A portable bound stays below Tokio's semaphore maximum on 32-bit targets.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct McpHttpLimits {
    #[serde(deserialize_with = "deserialize_mcp_limit")]
    pub sessions: u32,
    #[serde(deserialize_with = "deserialize_mcp_limit")]
    pub requests: u32,
    #[serde(deserialize_with = "deserialize_mcp_limit")]
    pub calls: u32,
    #[serde(deserialize_with = "deserialize_mcp_limit")]
    pub streams: u32,
}

impl McpHttpLimits {
    pub const MAX: u32 = 1_000_000;

    pub fn validate(self) -> anyhow::Result<()> {
        for (name, value) in [("sessions", self.sessions), ("requests", self.requests),
            ("calls", self.calls), ("streams", self.streams)] {
            anyhow::ensure!(value <= Self::MAX, "{name} must be an integer from 0 to {} (0 = unlimited)", Self::MAX);
        }
        Ok(())
    }

    /// Shared by the desktop and CLI. Do not silently clamp or truncate input.
    pub fn parse_inputs(sessions: &str, requests: &str, calls: &str, streams: &str) -> anyhow::Result<Self> {
        fn parse(name: &str, text: &str) -> anyhow::Result<u32> {
            anyhow::ensure!(!text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()),
                "{name} must be an integer from 0 to {} (0 = unlimited)", McpHttpLimits::MAX);
            text.parse::<u32>().map_err(|_| anyhow::anyhow!("{name} must be an integer from 0 to {} (0 = unlimited)", McpHttpLimits::MAX))
        }
        let value = Self { sessions: parse("sessions", sessions)?, requests: parse("requests", requests)?,
            calls: parse("calls", calls)?, streams: parse("streams", streams)? };
        value.validate()?;
        Ok(value)
    }
}

// Require the profile field to be a JSON object. Serde's derived struct
// visitor also accepts sequences; an empty array must not silently mean zero.
fn deserialize_mcp_http_limits<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<McpHttpLimits, D::Error> {
    struct LimitsVisitor;
    impl<'de> serde::de::Visitor<'de> for LimitsVisitor {
        type Value = McpHttpLimits;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an object containing HTTP MCP limits")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            McpHttpLimits::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(LimitsVisitor)
}

fn deserialize_mcp_limit<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let value = u32::deserialize(deserializer)?;
    if value > McpHttpLimits::MAX {
        return Err(serde::de::Error::custom(format!("MCP limit must be from 0 to {} (0 = unlimited)", McpHttpLimits::MAX)));
    }
    Ok(value)
}

/// On-disk layout. Keep additive to ease forward-compat.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub sessions: Vec<Session>,
    /// User-managed WSL launch entries. An empty list keeps the implicit default
    /// WSL entry for backwards compatibility.
    #[serde(default)]
    pub wsl_profiles: Vec<WslProfile>,
    /// Preset SFTP download directory. Empty = ask each time.
    #[serde(default)]
    pub download_dir: String,
    /// UI language code: "zh" (default) or "en".
    #[serde(default)]
    pub language: String,
    /// Theme preference: "system" (default) | "dark" | "light".
    #[serde(default)]
    pub theme_pref: String,
    /// Platform renderer preference. Windows uses software/auto/gpu; macOS uses
    /// software/femtovg/skia. Missing or foreign-platform values use the platform default.
    #[serde(default)]
    pub renderer_mode: String,
    /// Terminal font family. Empty = the built-in default ("Meatshell Mono").
    #[serde(default)]
    pub font_family: String,
    /// Terminal font size in px. 0 = the built-in default.
    #[serde(default)]
    pub font_size: u32,
    /// Terminal line-height multiplier. 0 means the default 1.0.
    #[serde(default)]
    pub terminal_line_spacing: f32,
    /// Force regular terminal text to render with a bold face (#262).
    #[serde(default)]
    pub terminal_bold: bool,
    /// Terminal insertion cursor shape: block (default), bar, or underline (#275).
    #[serde(default)]
    pub terminal_cursor_style: String,
    /// Custom terminal cursor colour as #RRGGBB. Empty follows the theme (#275).
    #[serde(default)]
    pub terminal_cursor_color: String,
    /// Stored inverted so missing/legacy config keeps the automatic plain-text
    /// output highlighter enabled by default.
    #[serde(default)]
    pub output_highlight_disabled: bool,
    /// Built-in output highlight preset: "log" (default) or "devops".
    #[serde(default)]
    pub output_highlight_preset: String,
    /// User-defined rules applied before the selected built-in preset.
    #[serde(default)]
    pub output_highlight_rules: Vec<OutputHighlightRule>,
    /// Stored inverted so complete JSON lines are formatted and syntax-coloured
    /// by default while still allowing users to preserve byte-for-byte display.
    #[serde(default)]
    pub json_format_disabled: bool,
    /// Record terminal output of new tabs to plain-text session logs (#265).
    /// Off by default; saved sessions can override it either way.
    #[serde(default)]
    pub session_log_enabled: bool,
    /// Folder for session logs. Empty = `<log dir>/sessions`.
    #[serde(default)]
    pub session_log_dir: String,
    /// Global UI scale in percent (#100). 0 = default (100%).
    #[serde(default)]
    pub ui_scale: u32,
    /// Immersive wallpaper id: "" = none, "builtin:light" / "builtin:dark" /
    /// "builtin:tech", or a filesystem path to a custom image. Drives the
    /// wallpaper + tinted theme. Defaults to the "幻想 3048" built-in.
    #[serde(default = "default_wallpaper")]
    pub wallpaper: String,
    /// Explicit session groups/folders (#41), including empty ones so a folder
    /// can exist before any session is moved into it. "default" is implicit and
    /// not stored here.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Quick Connect folders that were collapsed when the UI was last used.
    /// `None` is a legacy/new config and starts with every folder collapsed;
    /// `Some([])` means the user explicitly expanded every folder.
    #[serde(default)]
    pub collapsed_session_groups: Option<Vec<String>>,
    /// Stored inverted ("don't follow") so both serde and the Default derive
    /// yield `false` = the feature defaults to ON: the SFTP panel follows the
    /// terminal's cd (OSC 7) unless the user opts out in Interface settings.
    #[serde(default)]
    pub sftp_no_follow_cd: bool,
    /// Always prompt for the save location on each download instead of using the
    /// preset download dir. Defaults to false (#87).
    #[serde(default)]
    pub download_always_ask: bool,
    /// Hide the quick-command bar under the terminal. Defaults to false.
    #[serde(default)]
    pub hide_cmd_bar: bool,
    /// Stored inverted so multiline paste confirmation remains enabled for
    /// existing configurations unless the user explicitly disables it (#300).
    #[serde(default)]
    pub paste_confirm_disabled: bool,
    /// Stored inverted so Ctrl+Alt+V, Shift+Insert, and middle-click paste stay
    /// enabled for existing users (#300).
    #[serde(default)]
    pub extra_paste_shortcuts_disabled: bool,
    /// Hide auxiliary panels and edge strips so the terminal fills the window.
    #[serde(default)]
    pub zen_mode: bool,
    /// Saved quick commands (#55).
    #[serde(default)]
    pub quick_commands: Vec<QuickCommand>,
    /// Explicit quick-command group names — mirrors `groups` for sessions so that
    /// empty quick-command groups survive and can be renamed/deleted (#55).
    #[serde(default)]
    pub quick_groups: Vec<String>,
    /// Opt-in docked quick-command sidebar (#215). The command-bar popup remains
    /// available until the user actually drags it into the main dock layer.
    #[serde(default)]
    pub quick_commands_as_sidebar: bool,
    #[serde(default)]
    pub quick_panel_open: bool,
    #[serde(default)]
    pub quick_panel_collapsed: bool,
    #[serde(default = "default_quick_panel_width")]
    pub quick_panel_width: f32,
    #[serde(default = "default_quick_panel_height")]
    pub quick_panel_height: f32,
    #[serde(default)]
    pub quick_panel_dock: String,
    /// Recent commands sent from the command box, oldest first, capped (#55).
    #[serde(default)]
    pub command_history: Vec<String>,
    /// Collapse the left resource sidebar on startup (#78).
    #[serde(default)]
    pub collapse_sidebar_default: bool,
    /// Last resource-sidebar collapsed state. None means fall back to
    /// `collapse_sidebar_default` for older configs.
    #[serde(default)]
    pub sidebar_collapsed: Option<bool>,
    /// User-adjustable width of the left resource sidebar, in logical pixels.
    /// Persisted across restarts so the drag-resized width sticks.
    #[serde(default = "default_sidebar_width")]
    pub sidebar_width: f32,
    /// Resource-panel docking: size when docked top/bottom, and which edge it is
    /// docked to (left|right|top|bottom). Persisted so the layout sticks (#dock).
    #[serde(default = "default_sidebar_height")]
    pub sidebar_height: f32,
    #[serde(default)]
    pub sidebar_dock: String,
    /// SFTP-panel docking: extents (px) and docked edge, persisted (#dock).
    #[serde(default = "default_sftp_width")]
    pub sftp_panel_width: f32,
    #[serde(default = "default_sftp_height")]
    pub sftp_panel_height: f32,
    #[serde(default = "default_sftp_tree_width")]
    pub sftp_tree_width: f32,
    #[serde(default)]
    pub sftp_dock: String,
    /// Columns shown in the SFTP file list. Unknown values are ignored by the
    /// accessor so newer builds can safely read older or hand-edited configs.
    #[serde(default = "default_sftp_visible_columns")]
    pub sftp_visible_columns: Vec<String>,
    /// Last window size in logical px (0 = unset → use the built-in default).
    /// Lets users keep their preferred window size across restarts.
    #[serde(default)]
    pub window_width: f32,
    #[serde(default)]
    pub window_height: f32,
    /// Collapse the bottom SFTP panel on startup (#78).
    #[serde(default)]
    pub collapse_sftp_default: bool,
    /// When session-sync is on, also mirror SFTP uploads to the other online
    /// sessions (same path, falling back to each panel's current dir).
    #[serde(default)]
    pub sync_upload: bool,
    /// WebDAV sync settings (#185). Password is encrypted at rest like session
    /// passwords; remote_path is the JSON export object path under the endpoint.
    #[serde(default)]
    pub webdav_enabled: bool,
    #[serde(default)]
    pub webdav_url: String,
    #[serde(default)]
    pub webdav_username: String,
    #[serde(default)]
    pub webdav_password: Secret,
    #[serde(default)]
    pub webdav_remote_path: String,
    #[serde(default)]
    pub webdav_accept_invalid_certs: bool,
    /// Render the welcome page (session list) as a docked left sidebar instead of
    /// a "New tab" tab (v0.5). Persisted so the layout choice sticks.
    #[serde(default)]
    pub welcome_as_sidebar: bool,
    /// Width (logical px) of the welcome/session sidebar when docked (v0.5).
    #[serde(default)]
    pub welcome_sidebar_width: f32,
    /// Welcome/session sidebar dock edge (left|right|top|bottom).
    #[serde(default)]
    pub welcome_sidebar_dock: String,
    /// Welcome sidebar collapsed to the edge icon strip (IDEA-style) (v0.5).
    /// None means the user has not explicitly collapsed/expanded it yet.
    #[serde(default)]
    pub welcome_collapsed: Option<bool>,
    /// Frosted-panel opacity over a wallpaper (0.30–1.00); user-adjustable via the
    /// Interface › Wallpaper opacity slider. 0 = use the current default.
    #[serde(default)]
    pub wallpaper_overlay: f32,
    /// Settings-panel font scale, percent (80–160). 0 = 100% default (v0.5).
    #[serde(default)]
    pub panel_font: u32,
    /// Disable the startup "new version available" check (#184). Default false =
    /// keep checking (preserves existing behaviour for upgrading users); turning
    /// it on stops the GitHub releases query and the banner.
    #[serde(default)]
    pub update_check_disabled: bool,
    /// Enable the local stdio MCP server (`meatshell mcp serve`).
    #[serde(default = "default_mcp_preview_enabled")]
    pub mcp_enabled: bool,
    /// Allow MCP tools to use credentials already stored by MeatShell. Secrets
    /// remain internal and are never included in protocol responses.
    #[serde(default = "default_mcp_preview_enabled")]
    pub mcp_use_saved_credentials: bool,
    /// Allow MCP clients to execute arbitrary commands on saved SSH sessions.
    #[serde(default = "default_mcp_preview_enabled")]
    pub mcp_allow_commands: bool,
    /// Allow MCP clients to upload local files and download remote files.
    #[serde(default = "default_mcp_preview_enabled")]
    pub mcp_allow_file_transfers: bool,
    /// Per-profile authenticated HTTP limits; missing fields are unlimited.
    #[serde(default, deserialize_with = "deserialize_mcp_http_limits")]
    pub mcp_http_limits: McpHttpLimits,
    /// One-time default-layout migration marker (#new-user-defaults). 0 = config
    /// predates the migration. `migrate_defaults` bumps it to `DEFAULTS_REV` after
    /// pushing the new look (default wallpaper / welcome-as-sidebar / right-docked
    /// resource panel / wallpaper overlay) to users still sitting on old defaults.
    #[serde(default)]
    pub defaults_rev: u32,
    /// Per-edge stacks of simultaneously-expanded docked panels (#dock-stack),
    /// e.g. session list + Quick shared on the left edge, split vertically.
    /// Empty (or <2 slots on a valid edge) → the legacy single-panel-per-edge
    /// layout.
    #[serde(default)]
    pub dock_stacks: Vec<DockEdgeSer>,
}

/// Portable export file (issue #46): sessions with everything in plaintext
/// **except** the password, which is encrypted with a fixed key baked into the
/// binary so the file opens on *any* machine running meatshell.
///
/// Security note: a built-in key in open-source code is **obfuscation, not real
/// security** — anyone with the source can derive it. It only stops a casual
/// over-the-shoulder read of the file, same level as FinalShell's export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExportFile {
    /// Format marker / version so the schema can evolve later.
    pub(crate) meatshell_export: u32,
    pub(crate) sessions: Vec<Session>,
}

#[cfg(test)]
mod mcp_limits_tests {
    use super::*;

    #[test]
    fn missing_and_partial_limits_are_unlimited() {
        let config: ConfigFile = serde_json::from_str("{}").unwrap();
        assert_eq!(config.mcp_http_limits, McpHttpLimits::default());
        let limits: McpHttpLimits = serde_json::from_str(r#"{"calls":3}"#).unwrap();
        assert_eq!(limits, McpHttpLimits { calls: 3, ..Default::default() });
        assert_eq!(serde_json::from_str::<McpHttpLimits>("{}").unwrap(), McpHttpLimits::default());
    }

    #[test]
    fn limits_reject_invalid_json_without_coercion() {
        for value in ["null", "-1", "0.5", "1.0", "true", "\"1\"", "1000001", "4294967296", "18446744073709551616"] {
            for field in ["sessions", "requests", "calls", "streams"] {
                let raw = format!(r#"{{"{field}":{value}}}"#);
                assert!(serde_json::from_str::<McpHttpLimits>(&raw).is_err(), "accepted {raw}");
            }
        }
        assert!(serde_json::from_str::<McpHttpLimits>(r#"{"call":1}"#).is_err());
        for value in ["null", "[]", "[1,2,3,4]", "\"invalid\""] {
            assert!(serde_json::from_str::<ConfigFile>(&format!(r#"{{"mcp_http_limits":{value}}}"#)).is_err());
        }
        assert!(serde_json::from_str::<ConfigFile>(r#"{"mcp_http_limits":{"calls":1,"calls":2}}"#).is_err());
    }

    #[test]
    fn shared_input_parser_checks_range_and_overflow() {
        for invalid in ["", " ", " 1", "1 ", "+1", "-1", "1.0", "1e2", "NaN", "1000001", "4294967296", "18446744073709551616", "１"] {
            assert!(McpHttpLimits::parse_inputs(invalid, "0", "0", "0").is_err(), "accepted {invalid}");
            assert!(McpHttpLimits::parse_inputs("0", invalid, "0", "0").is_err());
            assert!(McpHttpLimits::parse_inputs("0", "0", invalid, "0").is_err());
            assert!(McpHttpLimits::parse_inputs("0", "0", "0", invalid).is_err());
        }
        let limits = McpHttpLimits::parse_inputs("0", "1", "0002", "1000000").unwrap();
        assert_eq!(limits, McpHttpLimits { sessions: 0, requests: 1, calls: 2, streams: McpHttpLimits::MAX });
        assert_eq!(serde_json::from_str::<McpHttpLimits>(&serde_json::to_string(&limits).unwrap()).unwrap(), limits);
    }
}
