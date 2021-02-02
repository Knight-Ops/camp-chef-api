use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub sub: String,
    pub aud: String,
    pub email_verified: String,
    pub event_id: String,
    pub token_use: String,
    pub auth_time: String,
    pub iss: String,
    #[serde(rename(serialize = "cognito:username", deserialize = "cognito:username"))]
    pub cognito_username: String,
    pub exp: String,
    pub given_name: String,
    pub iat: String,
    pub email: String,
    pub saved: String,
    pub id: usize,
}
