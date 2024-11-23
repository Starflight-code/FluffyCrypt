use std::fs::DirEntry;
use std::path::{Path, PathBuf};
use std::vec::Vec;

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
    println!("Hello, world!");
}
