use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Register {
    #[serde(rename(serialize = "certificateArn", deserialize = "certificateArn"))]
    pub certificate_arn: String,
    #[serde(rename(serialize = "certificateId", deserialize = "certificateId"))]
    pub certificate_id: String,
    #[serde(rename(serialize = "certificatePem", deserialize = "certificatePem"))]
    pub certificate_pem: String,
    #[serde(rename(serialize = "keyPair", deserialize = "keyPair"))]
    pub key_pair: KeyPair,
    #[serde(rename(serialize = "awsCA", deserialize = "awsCA"))]
    pub aws_ca: String,
    #[serde(rename(serialize = "thingName", deserialize = "thingName"))]
    pub thing_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyPair {
    #[serde(rename(serialize = "PublicKey", deserialize = "PublicKey"))]
    pub public_key: String,
    #[serde(rename(serialize = "PrivateKey", deserialize = "PrivateKey"))]
    pub private_key: String,
}
