use std::ops::Deref;

use reqwest;

pub mod user_v2_devices;
pub use user_v2_devices::{Device, UserV2Devices};

pub mod ota_esp;
pub use ota_esp::{EspVersion, OtaEsp};

pub mod snapshot_heartbeat;
pub use snapshot_heartbeat::SnapshotHeartbeat;

pub mod device_v2_heartbeat;
pub use device_v2_heartbeat::DeviceV2Heartbeat;

pub mod device_v2_flag_migrate;
pub use device_v2_flag_migrate::DeviceV2FlagMigrate;

pub mod register;
pub use register::{KeyPair, Register};

pub mod ota_stm;
pub use ota_stm::{OtaStm, StmVersion};

pub mod user;
pub use user::User;

#[derive(Debug)]
struct ResponseError(String);

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ResponseError : {}", self.0)
    }
}

impl std::error::Error for ResponseError {}

#[derive(Debug, Clone)]
pub struct CampChefAPI {
    pub client: reqwest::Client,
    api_base: String,
}

impl CampChefAPI {
    pub fn new(auth_header: String) -> Result<Self, Box<dyn std::error::Error>> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, auth_header.parse().unwrap());

        Ok(CampChefAPI {
            client: reqwest::ClientBuilder::new()
                .default_headers(headers)
                .build()?,
            api_base: String::from("https://api.campchef.site/"),
        })
    }

    pub fn get_api_base(&self) -> String {
        self.api_base.to_owned()
    }

    pub async fn get_v2_devices(&self) -> Result<UserV2Devices, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get(&format!("{}user-v2/devices", &self.api_base))
            .send()
            .await?;

        let devices = response.json::<UserV2Devices>().await?;

        Ok(devices)
    }

    /// This is untested and will likely fail due to a bad response
    pub async fn delete_device(
        &self,
        device: &str,
    ) -> Result<UserV2Devices, Box<dyn std::error::Error>> {
        let response = self
            .client
            .delete(&format!("{}user/device/{}", &self.api_base, device))
            .send()
            .await?;

        let devices = response.json::<UserV2Devices>().await?;

        Ok(devices)
    }

    /// This is untested and will likely fail due to a bad response
    pub async fn delete_v2_device(
        &self,
        device: &str,
    ) -> Result<UserV2Devices, Box<dyn std::error::Error>> {
        let response = self
            .client
            .delete(&format!("{}user-v2/device/{}", &self.api_base, device))
            .send()
            .await?;

        let devices = response.json::<UserV2Devices>().await?;

        Ok(devices)
    }

    pub async fn get_ota_esp(&self, version: &str) -> Result<OtaEsp, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get(&format!("{}ota/esp/{}", &self.api_base, version))
            .send()
            .await?;

        let ota_esp = response.json::<OtaEsp>().await?;

        Ok(ota_esp)
    }

    pub async fn get_snapshot_heartbeat(
        &self,
        mac: &str,
    ) -> Result<SnapshotHeartbeat, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get(&format!("{}snapshot/{}/hearbeat", &self.api_base, mac))
            .send()
            .await?;

        let snapshot_heartbeat = response.json::<SnapshotHeartbeat>().await?;

        Ok(snapshot_heartbeat)
    }

    pub async fn get_device_v2_heartbeat(
        &self,
        mac: &str,
    ) -> Result<DeviceV2Heartbeat, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get(&format!("{}snapshot/{}/hearbeat", &self.api_base, mac))
            .send()
            .await?;

        let device_v2_heartbeat = response.json::<DeviceV2Heartbeat>().await?;

        Ok(device_v2_heartbeat)
    }

    pub async fn get_device_v2_flag_migrate(
        &self,
        device: &str,
        mac: &str,
    ) -> Result<DeviceV2FlagMigrate, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get(&format!(
                "{}device-v2/{}/{}/flag/migrate",
                &self.api_base, device, mac
            ))
            .send()
            .await?;

        let device_v2_flag_migrate = response.json::<DeviceV2FlagMigrate>().await?;

        Ok(device_v2_flag_migrate)
    }

    pub async fn get_register(&self, device: &str) -> Result<Register, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get(&format!("{}register/{}", &self.api_base, device))
            .send()
            .await?;

        let response_text = response.text().await?;

        let register: Register = match serde_json::from_str(&response_text) {
            Ok(reg) => reg,
            Err(_) => return Err(Box::new(ResponseError(response_text))),
        };

        Ok(register)
    }

    pub async fn get_ota_stm(&self, version: &str) -> Result<OtaStm, Box<dyn std::error::Error>> {
        let split_version: Vec<&str> = version.split(" V").collect();
        let model = split_version[0];
        let version_num = split_version[1];

        let response = self
            .client
            .get(&format!(
                "{}ota/stm/{}/{}",
                &self.api_base, model, version_num
            ))
            .send()
            .await?;

        let ota_stm = response.json::<OtaStm>().await?;

        Ok(ota_stm)
    }

    pub async fn get_user(&self) -> Result<User, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get(&format!("{}user/", &self.api_base))
            .send()
            .await?;

        let user = response.json::<User>().await?;

        Ok(user)
    }
}

// impl Deref for CampChefAPI {
//     type Target = reqwest::Client;

//     fn deref(&self) -> &reqwest::Client {
//         &self.client
//     }
// }

#[cfg(test)]
mod test {
    use super::*;
}
