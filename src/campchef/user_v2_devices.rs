use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserV2Devices {
    pub status: String,
    pub source: String,
    pub devices: Vec<Device>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Device {
    pub nickname: String,
    pub stm32: String,
    pub seconds: usize,
    pub esp32: String,
    pub device: String,
    pub mac: String,
}
