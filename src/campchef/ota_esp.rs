// "{\"latest\":true,\"do_update\":false,\"url\":\"https://ota.campchef.site/esp/esp_1.3.2.bin\",\"md5sum\":\"5660e328d2eb551d3c7d1e50b47ed02f\",\"version\":\"1.3.2\",\"publishDate\":\"2020-07-13\",\"notes\":\"\",\"alternate\":{\"1.4.1-debug\":{\"url\":\"https://ota.campchef.site/esp/esp_1.4.1-dbg.bin\",\"md5sum\":\"0dd38ddd32e5cbda9dae741ec285c968\"},\"1.3.2-debug\":{\"url\":\"https://ota.campchef.site/esp/esp_1.3.2-dbg.bin\",\"md5sum\":\"3213eb8b50a59ac41969796e5b867d6d\"},\"1.2.1\":{\"url\":\"https://ota.campchef.site/esp/esp_1.2.1.bin\",\"md5sum\":\"e50db54d8ca97311275efa782ff75474\"},\"1.1.6\":{\"url\":\"https://ota.campchef.site/esp/firmware_1.1.6.bin\",\"md5sum\":\"25c075dc9d109251fe5fcb16a6e9b220\"},\"1.1.5\":{\"url\":\"https://ota.campchef.site/esp/firmware_1.1.5.bin\",\"md5sum\":\"f8c0b8ef90bdc30e183a2aef76721f0d\"}}}"

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OtaEsp {
    pub latest: bool,
    pub do_update: bool,
    pub url: String,
    pub md5sum: String,
    pub version: String,
    #[serde(rename(serialize = "publishDate", deserialize = "publishDate"))]
    pub publish_date: String,
    pub notes: String,
    pub alternate: HashMap<String, EspVersion>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EspVersion {
    pub url: String,
    pub md5sum: String,
}
