use std::{fs::DirEntry, path::PathBuf};

use crossbeam_channel::Sender;
use tracing::{event, Level};

/// provides directory scanning using recursion, returns result
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
    Some(files)
}

/// provides directory scanning using recursion, sends files to `sender` when found
pub(crate) fn recurse_directory_with_channel(path: PathBuf, sender: &Sender<DirEntry>) {
    if path.read_dir().is_err() {
        return;
    }
    let mut directories = Vec::new();
    for file in path.read_dir().unwrap() {
        if file.is_err() {
            continue;
        }
        let file = file.unwrap();

        if file.path().is_dir() {
            event!(Level::DEBUG, "Found directory: {:?}", file.path());
            directories.push(file.path());
        } else if file.path().is_file() {
            event!(Level::DEBUG, "Found file: {:?}", file.path());
            let _ = sender.send(file);
        }
    }

    for directory in directories {
        recurse_directory_with_channel(directory, sender);
    }
}
