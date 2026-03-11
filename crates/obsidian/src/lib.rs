//! Hooks for the [cadence-obsidian](https://github.com/cameronsjo/cadence-obsidian) plugin.
//!
//! Obsidian vault-aware guards that preserve Obsidian's recoverability model.

/// Block `rm` inside an Obsidian vault — files should be moved to `.trash/` instead.
pub mod trash_guard;
