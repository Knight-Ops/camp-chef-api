pub mod aws_creds;
pub mod aws_srp_helper;

pub use aws_creds::*;
pub use aws_srp_helper::*;

use chrono::{TimeZone, Utc};
use rusoto_cognito_identity::{CognitoIdentity, CognitoIdentityClient};
use rusoto_cognito_idp;
use rusoto_cognito_idp::{CognitoIdentityProvider, CognitoIdentityProviderClient};
use rusoto_core::{
    credential::AutoRefreshingProvider, credential::AwsCredentials,
    credential::ProvideAwsCredentials, Client, HttpClient, Region,
};
use rusoto_iot::{Iot, IotClient};
use std::collections::HashMap;

async fn aws_get_id(id_pool: String, region: Region) -> Result<String, Box<dyn std::error::Error>> {
    let rusoto_client =
        Client::new_not_signing(HttpClient::new().expect("Failed to create request dispatcher"));
    let client = CognitoIdentityClient::new_with_client(rusoto_client, region);

    let get_id_input = rusoto_cognito_identity::GetIdInput {
        account_id: None,
        identity_pool_id: id_pool,
        logins: Some(HashMap::new()),
    };

    let output = client.get_id(get_id_input).await?;

    // println!("{:?}", output);

    if let Some(identity_id) = output.identity_id {
        Ok(identity_id)
    } else {
        Err("Error obtaining Identity Id".into())
    }
}

async fn aws_get_credentials_for_id(
    id: String,
    region: Region,
) -> Result<rusoto_cognito_identity::GetCredentialsForIdentityResponse, Box<dyn std::error::Error>>
{
    let rusoto_client =
        Client::new_not_signing(HttpClient::new().expect("Failed to create request dispatcher"));
    let client = CognitoIdentityClient::new_with_client(rusoto_client, region);

    let get_credentials_for_id_input = rusoto_cognito_identity::GetCredentialsForIdentityInput {
        custom_role_arn: None,
        identity_id: id,
        logins: Some(HashMap::new()),
    };

    let output = client
        .get_credentials_for_identity(get_credentials_for_id_input)
        .await?;

    // println!("{:?}", output);

    Ok(output)
}

async fn aws_start_auth(
    client_id: String,
    region: Region,
    creds: CredentialsFromIdentityResponse,
    srp_helper: &AwsSrpHelper,
) -> Result<rusoto_cognito_idp::InitiateAuthResponse, Box<dyn std::error::Error>> {
    let client = CognitoIdentityProviderClient::new_with(
        HttpClient::new().expect("Failed to create request dispatcher"),
        AutoRefreshingProvider::new(creds).unwrap(),
        region,
    );

    let auth_request = rusoto_cognito_idp::InitiateAuthRequest {
        analytics_metadata: None,
        auth_flow: String::from("USER_SRP_AUTH"),
        auth_parameters: Some(srp_helper.get_auth_parameters()),
        client_id: client_id,
        client_metadata: None,
        user_context_data: None,
    };
    // println!("Auth Request : {:?}", auth_request);

    Ok(client.initiate_auth(auth_request).await?)
}

async fn aws_respond_to_auth_challenge(
    client_id: String,
    region: Region,
    creds: CredentialsFromIdentityResponse,
    auth: HashMap<String, String>,
    srp_helper: &AwsSrpHelper,
) -> Result<rusoto_cognito_idp::RespondToAuthChallengeResponse, Box<dyn std::error::Error>> {
    let client = CognitoIdentityProviderClient::new_with(
        HttpClient::new().expect("Failed to create request dispatcher"),
        AutoRefreshingProvider::new(creds).unwrap(),
        region,
    );

    let internal_username = auth
        .get("USERNAME")
        .expect("Error retrieving USERNAME from HashMap")
        .to_owned();
    let user_id_for_srp = auth
        .get("USER_ID_FOR_SRP")
        .expect("Error retrieving USER_ID_FOR_SRP from HashMap")
        .to_owned();
    let salt_hex = auth
        .get("SALT")
        .expect("Error retrieving SALT from HashMap")
        .to_owned();
    let srp_b_hex = auth
        .get("SRP_B")
        .expect("Error retrieving SRP_B from HashMap")
        .to_owned();
    let secret_block_b64 = auth
        .get("SECRET_BLOCK")
        .expect("Error retrieving SECRET_BLOCK from HashMap")
        .to_owned();

    let auth_response = rusoto_cognito_idp::RespondToAuthChallengeRequest {
        analytics_metadata: None,
        user_context_data: None,
        client_metadata: None,
        session: None,
        client_id: client_id,
        challenge_name: String::from("PASSWORD_VERIFIER"),
        challenge_responses: Some(srp_helper.get_challenge_response(
            internal_username,
            user_id_for_srp,
            salt_hex,
            srp_b_hex,
            secret_block_b64,
        )),
    };

    // println!("{:?}", auth_response);

    Ok(client.respond_to_auth_challenge(auth_response).await?)
}

async fn aws_iot_get_certs(
    region: Region,
    creds: CredentialsFromIdentityResponse,
) -> Result<rusoto_iot::CreateKeysAndCertificateResponse, Box<dyn std::error::Error>> {
    let client = IotClient::new_with(
        HttpClient::new().expect("Failed to create request dispatcher"),
        AutoRefreshingProvider::new(creds).unwrap(),
        region,
    );
    let cert_request = rusoto_iot::CreateKeysAndCertificateRequest {
        set_as_active: None,
    };

    Ok(client.create_keys_and_certificate(cert_request).await?)
}

pub struct AuthInitiated {
    username: String,
    password: String,
    identity_pool_id: String,
    user_pool_id: String,
    client_id: String,
    client_secret: String,
    region: Region,
}

impl AuthInitiated {
    pub fn new(username: String, password: String) -> Self {
        AuthInitiated {
            username,
            password,
            identity_pool_id: "us-west-2:d2fb83c5-bf3c-4604-a4ae-c7c629b78444".into(),
            user_pool_id: "us-west-2_6pjAdMAdn".into(),
            client_id: "4nnvoimmmgejnb5j8q5bctvj4i".into(),
            client_secret: "mp85puvu1erob6ccr6a1k8od1legl1gu8cogl158ec97iatjtpj".into(),
            region: Region::UsWest2,
        }
    }
}

pub struct AuthCompleted {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: String,
}

pub async fn authenticate_to_aws_cognito(
    auth_info: AuthInitiated,
) -> Result<AuthCompleted, Box<dyn std::error::Error>> {
    let identity_id = aws_get_id(auth_info.identity_pool_id, auth_info.region.clone()).await?;
    // println!("{:?}", identity_id);

    let creds = aws_get_credentials_for_id(identity_id, auth_info.region.clone()).await?;
    // println!("{:?}", creds);

    let client_creds = CredentialsFromIdentityResponse::new(creds);
    // println!("{:?}", client_creds);

    // let certs = aws_iot_get_certs(auth_info.region.clone(), client_creds.clone()).await?;
    // println!("{:?}", certs);

    let srp_helper = AwsSrpHelper::new(
        auth_info.username,
        auth_info.password,
        auth_info.user_pool_id,
        auth_info.client_id.clone(),
        auth_info.client_secret,
    );
    // println!("{:?}", srp_helper);

    let auth = aws_start_auth(
        auth_info.client_id.clone(),
        auth_info.region.clone(),
        client_creds.clone(),
        &srp_helper,
    )
    .await?;
    // println!("{:?}", auth);

    let auth_resp = if let Some(chal) = auth.challenge_name {
        match chal.as_str() {
            "PASSWORD_VERIFIER" => {
                aws_respond_to_auth_challenge(
                    auth_info.client_id.clone(),
                    auth_info.region,
                    client_creds.clone(),
                    auth.challenge_parameters
                        .expect("Challenge Parameters are missing from Response!"),
                    &srp_helper,
                )
                .await?
            }
            _ => unimplemented!("Challenge is not implemented"),
        }
    } else {
        unreachable!("Challenge Name empty!");
    };
    // println!("{:?}", auth_resp);

    let auth_results = auth_resp.authentication_result.unwrap();

    Ok(AuthCompleted {
        access_token: auth_results.access_token.unwrap(),
        id_token: auth_results.id_token.unwrap(),
        refresh_token: auth_results.refresh_token.unwrap(),
    })
}
