use mqtt::{subscribe_firehose, subscribe_wildcard};
use reqwest;

mod aws_srp;
use aws_srp::{AuthCompleted, AuthInitiated};

mod mqtt;

mod campchef;

use tokio::prelude::*;
use tokio::task;

use rumqttc::{AsyncClient, QoS};
use text_io::read;

use futures::channel::oneshot;

use clap::{App, Arg};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("Camp Chef API")
        .version("1.0")
        .author("Carl Hurd <carl@basilisklabs.com")
        .about("Connects to the Camp Chef MQTT server and exposes the API from CampChef")
        .arg(
            Arg::with_name("username")
                .short("u")
                .required(true)
                .help("Username for authentication")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .required(true)
                .help("Password for authentication")
                .takes_value(true),
        )
        .get_matches();
    let auth_info = AuthInitiated::new(matches.value_of("username").unwrap().into(), matches.value_of("password").unwrap().into());
    let auth_resp = aws_srp::authenticate_to_aws_cognito(auth_info).await?;

    println!("ID TOKEN : {}", auth_resp.id_token);

    let client = campchef::CampChefAPI::new(auth_resp.id_token)?;
    let devices = client.get_v2_devices().await?;
    let ota_esp = client.get_ota_esp(&devices.devices[0].esp32).await?;
    let register = client.get_register(&devices.devices[0].device).await?;

    println!("{:?}", devices);
    println!("{:?}", ota_esp);

    let mqtt_config = mqtt::configure_mqtt_options(
        "af4cmuugvxisx-ats.iot.us-west-2.amazonaws.com",
        8883,
        &register.aws_ca,
        &register.certificate_pem,
        &register.key_pair.private_key,
    )
    .await?;

    let mqtt_client = {
        let (mut tx, mut rx) = oneshot::channel::<AsyncClient>();

        task::spawn(async {
            mqtt::connect_to_mqtt_server(mqtt_config, tx).await;
        });

        rx.await
            .expect("Never received AsyncClient for MQTT setup!")
    };

    mqtt::subscribe_device_all(&mqtt_client, &devices.devices[0].mac).await?;

    // mqtt_client
    //     .subscribe("snapshot/v2/accepted", QoS::AtMostOnce)
    //     .await
    //     .unwrap();

    loop {}

    Ok(())
}
