// "{\"status\":\"success\",\"seconds\":\"9999999\"}"
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SnapshotHeartbeat {
    pub status: String,
    pub seconds: String,
}
