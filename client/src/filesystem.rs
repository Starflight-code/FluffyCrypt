use std::{fs::DirEntry, path::PathBuf};

use crossbeam_channel::Sender;

#[allow(dead_code)]
pub(crate) fn recurse_directory(path: PathBuf) -> Option<Vec<DirEntry>> {
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

pub(crate) fn recurse_directory_with_channel(path: PathBuf, sender: &Sender<DirEntry>) {
    if path.read_dir().is_err() {
        return;
    }
    for file in path.read_dir().unwrap() {
        if file.is_err() {
            continue;
        }
        let file = file.unwrap();

        if file.path().is_dir() {
            recurse_directory_with_channel(file.path(), sender);
        } else if file.path().is_file() {
            let _ = sender.send(file);
        }
    }
}
