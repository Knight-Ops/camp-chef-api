use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use rusoto_cognito_identity;
use rusoto_core::{
    credential::AwsCredentials, credential::CredentialsError, credential::ProvideAwsCredentials,
};

#[derive(Debug, Clone)]
pub struct CredentialsFromIdentityResponse {
    aws_credentials: AwsCredentials,
}

impl CredentialsFromIdentityResponse {
    pub fn new(ir: rusoto_cognito_identity::GetCredentialsForIdentityResponse) -> Self {
        let credentials = ir
            .credentials
            .expect("Credentials struct not found in GetCredentialsForIdentityResponse");
        let aws_credentials = AwsCredentials::new(
            credentials.access_key_id.unwrap(),
            credentials.secret_key.unwrap(),
            credentials.session_token,
            Some(Utc.timestamp(credentials.expiration.unwrap() as i64, 0)),
        );

        CredentialsFromIdentityResponse { aws_credentials }
    }
}

#[async_trait]
impl ProvideAwsCredentials for CredentialsFromIdentityResponse {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        Ok(self.aws_credentials.clone())
    }
}
