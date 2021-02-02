// "{\"status\":\"success\",\"seconds\":\"9999999\"}"
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceV2Heartbeat {
    pub status: String,
    pub seconds: String,
}
