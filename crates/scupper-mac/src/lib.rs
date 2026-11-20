//! The engine is the serialized macOS helper executor, with A/B snapshots and a
//! resource-model platform boundary. The engine mutation harnesses
//! `tests/engine_mutations.py` and `tests/mutants_7c.py` run manually before a
//! release of the Mac helper.
#![forbid(unsafe_code)]

pub mod decode;
pub mod engine;
pub mod platform;
#[cfg(feature = "qualification")]
pub mod qual;
pub mod snapshot;

pub use engine::{Completion, Engine, Mode, Outcome, QueueEvent, Request, RequestKind, Status};
