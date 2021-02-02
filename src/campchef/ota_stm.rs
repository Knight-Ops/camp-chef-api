use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OtaStm {
    pub latest: bool,
    pub do_update: bool,
    pub url: String,
    pub md5sum: String,
    pub version: String,
    #[serde(rename(serialize = "publishDate", deserialize = "publishDate"))]
    pub publish_date: String,
    pub notes: String,
    pub alternate: HashMap<String, StmVersion>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StmVersion {
    pub url: String,
    pub md5sum: String,
}
