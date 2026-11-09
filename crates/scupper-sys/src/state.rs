//! Strict, crash-safe persistence of operator selection and quarantine.

pub use crate::fs::DurableStep;
use crate::{
    fs::{Fs, RealFs, durable_directory, durable_replace},
    lock::WriterGuard,
};
pub use scupper_core::verdict::v2::Selection;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
};

/// Persisted safety latch; consumers must honor it before enabling forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quarantine {
    /// Why the repair budget was exhausted.
    pub reason: String,
    /// The object whose recurring drift triggered quarantine.
    pub object: String,
    /// Unix seconds when the latch was set.
    pub since_unix: u64,
}

/// On-disk state schema. Missing optional fields are refused, as are unknown fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// The supported state schema, currently 1.
    pub schema: u32,
    /// Last successfully applied immutable configuration version.
    #[serde(deserialize_with = "required_option")]
    pub applied_version: Option<u64>,
    /// Durable operator selection, including deliberate disconnection.
    pub selection: Selection,
    /// Persistent quarantine latch, cleared only by explicit administrative action.
    #[serde(deserialize_with = "required_option")]
    pub quarantine: Option<Quarantine>,
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
impl Default for State {
    fn default() -> Self {
        Self {
            schema: 1,
            applied_version: None,
            selection: Selection::Auto,
            quarantine: None,
        }
    }
}

/// Explicit result of reading the safety state. Absence is never an implicit reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateRead {
    /// A complete, validated persisted state.
    Present(State),
    /// No state file exists.
    Missing,
}

/// Boot's fail-closed decision, including the alert required for lost state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootState {
    /// Selection and quarantine to honor before enabling forwarding.
    pub state: State,
    /// Emit an alert: a configured system has lost its durable safety state.
    pub missing_state_alert: bool,
}

impl StateRead {
    /// Resolves absence for boot. With a config head, stay `Disconnected` and
    /// alert; do not persist a replacement that would hide the lost latch.
    /// Only a fresh install (no config head) creates the initial default state,
    /// explicitly using [`StateFile::write`] while holding the global lock.
    #[must_use]
    pub fn for_boot(self, has_config_head: bool) -> BootState {
        match self {
            Self::Present(state) => BootState {
                state,
                missing_state_alert: false,
            },
            Self::Missing => BootState {
                state: State {
                    selection: if has_config_head {
                        Selection::Disconnected
                    } else {
                        Selection::Auto
                    },
                    ..State::default()
                },
                missing_state_alert: has_config_head,
            },
        }
    }
}

/// State access rooted at `/var/lib/scupper` in production.
#[derive(Debug)]
pub struct StateFile {
    path: PathBuf,
}
impl StateFile {
    /// Chooses `root/state.json`. A writer guard enables stale-temp cleanup.
    /// No state file is created until an explicit write.
    ///
    /// # Errors
    /// Returns directory or stale-temp cleanup errors when a guard is supplied.
    pub fn open(root: impl AsRef<Path>, writer: Option<&WriterGuard>) -> io::Result<Self> {
        if writer.is_some() {
            durable_directory(root.as_ref())?;
            RealFs.cleanup_stale(root.as_ref())?;
        }
        Ok(Self {
            path: root.as_ref().join("state.json"),
        })
    }

    /// Reads strict schema 1, distinguishing absence from a persisted state.
    ///
    /// # Errors
    /// Returns corrupt JSON, unsupported schema, unsafe target, or I/O errors.
    pub fn read(&self) -> io::Result<StateRead> {
        match RealFs.read(&self.path) {
            Ok(text) => {
                let state: State = serde_json::from_str(&text)
                    .map_err(|_| io::Error::other("invalid state.json"))?;
                check_schema(&state)?;
                Ok(StateRead::Present(state))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(StateRead::Missing),
            Err(error) => Err(error),
        }
    }

    /// Durably replaces the entire state, using mode 0600.
    /// The guard proves the global writer lock is held for this transaction.
    ///
    /// ```compile_fail
    /// # use scupper_sys::state::{StateFile, State};
    /// fn unlocked(file: &StateFile) {
    ///     file.write(&State::default());
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns unsupported schema, serialization, or durability errors. An error
    /// after rename may leave the complete new state visible.
    pub fn write(&self, writer: &WriterGuard, state: &State) -> io::Result<()> {
        self.write_with_hook(writer, state, &|_| Ok(()))
    }

    /// Reads, modifies, and durably writes state under one global writer guard.
    /// Missing state requires an explicit boot/install decision, never a reset.
    ///
    /// # Errors
    /// Returns `NotFound` for missing state, or read/write/schema errors.
    pub fn update(
        &self,
        writer: &WriterGuard,
        change: impl FnOnce(&mut State),
    ) -> io::Result<State> {
        let StateRead::Present(mut state) = self.read()? else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "state.json is missing",
            ));
        };
        change(&mut state);
        self.write(writer, &state)?;
        Ok(state)
    }

    /// Writes state with a callback after each completed durability step.
    ///
    /// # Errors
    /// Returns write errors or the injected failure. Before rename the old file
    /// remains; after rename the new file remains.
    pub fn write_with_hook(
        &self,
        _writer: &WriterGuard,
        state: &State,
        hook: &dyn Fn(DurableStep) -> io::Result<()>,
    ) -> io::Result<()> {
        check_schema(state)?;
        let bytes = serde_json::to_vec(state).map_err(io::Error::other)?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("missing state directory"))?;
        durable_directory(parent)?;
        durable_replace(&RealFs, &self.path, &bytes, 0o600, &|_| Ok(()), hook)
    }
}
fn check_schema(state: &State) -> io::Result<()> {
    if state.schema == 1 {
        Ok(())
    } else {
        Err(io::Error::other("unsupported state.json schema"))
    }
}
