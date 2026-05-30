//! Experimental "lab" hooks for Claude Code.
//!
//! Currently houses the **self-representation persona ledger**: a two-hook system
//! that captures a constrained, per-session self-representation from the model and
//! appends it to an append-only JSONL ledger.
//!
//! - [`nudge::PersonaNudge`] — `SessionStart` hook; injects the contract.
//! - [`gate::PersonaGate`] — `PostToolUse(Write)` hook; validates and promotes.
//!
//! The namespace is `lab` (matching the `cadence-lab` plugin); `persona` is the
//! feature within it, leaving room for future lab experiments.

/// Runtime configuration: compiled defaults + optional JSON override.
pub mod config;
/// H2 — the `PostToolUse(Write)` validation/promotion gate.
pub mod gate;
/// H1 — the `SessionStart` contract nudge.
pub mod nudge;
/// Pure domain logic: validation, cheek heuristics, record construction.
pub mod persona;
