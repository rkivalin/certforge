use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Persistent state for tracking pre-publication and pending operations.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    /// Pending key rotations keyed by certificate name.
    #[serde(default)]
    pub pending_rotations: HashMap<String, PendingRotation>,
}

/// State for a pending key rotation with DANE pre-publication.
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingRotation {
    /// Path to the encrypted pending key
    pub pending_key_path: PathBuf,
    /// When the new TLSA was published
    pub published_at: DateTime<Utc>,
    /// The old TLSA TTL in seconds (we must wait this long)
    pub old_ttl: u32,
}

impl PendingRotation {
    /// Check if enough time has elapsed for the old TLSA TTL to expire.
    pub fn ttl_expired(&self) -> bool {
        let elapsed = Utc::now() - self.published_at;
        elapsed.num_seconds() >= self.old_ttl as i64
    }
}

impl State {
    /// Load state from the state directory.
    pub fn load(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join("state.json");
        if !path.exists() {
            return Ok(Self::default());
        }

        let data = std::fs::read_to_string(&path)
            .map_err(|e| Error::State(format!("failed to read state file: {e}")))?;
        let state: State = serde_json::from_str(&data)
            .map_err(|e| Error::State(format!("failed to parse state file: {e}")))?;
        Ok(state)
    }

    /// Save state to the state directory.
    pub fn save(&self, state_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(state_dir)?;
        let path = state_dir.join("state.json");
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| Error::State(format!("failed to serialize state: {e}")))?;
        std::fs::write(&path, data)?;
        Ok(())
    }
}
