use tokio::{task, time};

use rumqttc::{self, AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS};
use rustls::internal::msgs::codec::Codec;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use uuid;

fn read_cert(path: String) -> Vec<rustls::Certificate> {
    let mut file = File::open(path).expect("Error opening file");
    let mut buffile = BufReader::new(file);
    rumqttc::certs(&mut buffile).expect("Error")
}

fn read_key(path: String) -> rustls::PrivateKey {
    let mut file = File::open(path).expect("Error opening file");
    let mut buffile = BufReader::new(file);
    let keys = rumqttc::pkcs8_private_keys(&mut buffile).expect("Error");

    keys[0].clone()
}

pub async fn configure_mqtt_options(
    host: &str,
    port: u16,
    aws_ca: &str,
    client_cert: &str,
    client_private_key: &str,
) -> Result<MqttOptions, Box<dyn std::error::Error>> {
    let client_id = uuid::Uuid::new_v4();
    let mut mqttoptions = MqttOptions::new(format!("{}", client_id), host, port);
    mqttoptions.set_keep_alive(10);

    let mut rootStore = rustls::RootCertStore::empty();
    let mut ca_buffile = BufReader::new(aws_ca.as_bytes());
    let (added, skipped) = rootStore
        .add_pem_file(&mut ca_buffile)
        .expect("Error adding PEM file to rootStore");

    // println!("Added {} certificate(s) to the rootStore, skipped {} certificate(s)", added, skipped);

    let mut client_config = rumqttc::ClientConfig::new();
    client_config.root_store = rootStore;

    let mut cert_buffile = BufReader::new(client_cert.as_bytes());
    let cert_chain = rustls::internal::pemfile::certs(&mut cert_buffile)
        .expect("Error parsing priv key from file");

    let mut priv_key_buffile = BufReader::new(client_private_key.as_bytes());
    let priv_key = rustls::internal::pemfile::rsa_private_keys(&mut priv_key_buffile)
        .expect("Error parsing priv key from file");
    // println!("Adding cert to clientConfig : {:?}\nAdding private key to clientConfig : {:?}", cert_chain, priv_key);
    client_config
        .set_single_client_cert(cert_chain, priv_key[0].clone())
        .expect("Error adding cert_chain and priv_key to clientConfig");

    mqttoptions.set_tls_client_config(Arc::new(client_config));

    Ok(mqttoptions)
}

pub async fn connect_to_mqtt_server(
    options: MqttOptions,
    mut sender: futures::channel::oneshot::Sender<AsyncClient>,
) -> ! {
    let (client, mut eventloop) = AsyncClient::new(options, 20);

    sender
        .send(client)
        .expect("Error sending AsyncClient to main loop");

    loop {
        match eventloop.poll().await.expect("Error in event loop") {
            Event::Incoming(i) => match i {
                Packet::Publish(pkt) => {
                    println!("Packet = {:?}\nPacketData = {:?}", pkt, pkt.payload)
                }
                _ => {
                    println!("Other : {:?}", i);
                }
            },
            Event::Outgoing(o) => {
                println!("Outgoing = {:?}", o)
            }
        }
    }
}

pub async fn subscribe_device_all(
    client: &AsyncClient,
    mac: &str,
) -> Result<(), Box<std::error::Error>> {
    client
        .subscribe(
            &format!("$aws/things/{}/shadow/get/accepted", mac),
            QoS::AtMostOnce,
        )
        .await?;
    client
        .subscribe(
            &format!("$aws/things/{}/shadow/get/rejected", mac),
            QoS::AtMostOnce,
        )
        .await?;
    client
        .subscribe(
            &format!("$aws/things/{}/shadow/update/delta", mac),
            QoS::AtMostOnce,
        )
        .await?;
    client
        .subscribe(
            &format!("$aws/things/{}/shadow/update/accepted", mac),
            QoS::AtMostOnce,
        )
        .await?;
    client
        .subscribe(
            &format!("$aws/things/{}/shadow/update/documents", mac),
            QoS::AtMostOnce,
        )
        .await?;
    client
        .subscribe(
            &format!("$aws/things/{}/shadow/update/rejected", mac),
            QoS::AtMostOnce,
        )
        .await?;
    client
        .subscribe(
            &format!("$aws/things/{}/shadow/delete/accepted", mac),
            QoS::AtMostOnce,
        )
        .await?;
    client
        .subscribe(
            &format!("$aws/things/{}/shadow/delete/rejected", mac),
            QoS::AtMostOnce,
        )
        .await?;
    client
        .subscribe(&format!("{}/snapshot/v2", mac), QoS::AtMostOnce)
        .await?;
    client
        .subscribe(&format!("{}/heartbeat/v2", mac), QoS::AtMostOnce)
        .await?;

    Ok(())
}

pub async fn subscribe_firehose(client: &AsyncClient) -> Result<(), Box<std::error::Error>> {
    client
        .subscribe("snapshot/v2/accepted", QoS::AtMostOnce)
        .await?;
    Ok(())
}

pub async fn subscribe_wildcard(client: &AsyncClient) -> Result<(), Box<std::error::Error>> {
    client.subscribe("#", QoS::AtMostOnce).await?;
    Ok(())
}

pub async fn subscribe_app_disconnects(client: &AsyncClient) -> Result<(), Box<std::error::Error>> {
    client.subscribe("my/lwt/topic", QoS::AtMostOnce).await?;
    Ok(())
}
