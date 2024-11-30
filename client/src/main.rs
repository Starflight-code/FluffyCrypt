use std::fs::{self, DirEntry};
use std::io;
use std::path::Path;

fn list_files(dir_path: &str) -> io::Result<Vec<DirEntry>> {
    let mut files: Vec<DirEntry> = Vec::new();
    let entries = fs::read_dir(Path::new(dir_path))?;

    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let path = entry.path();
            let path_str = path.to_string_lossy().into_owned();
            let files_in_subdir = list_files(&path_str)?;
            files.extend(files_in_subdir);
        } else {
            files.push(entry);
        }
    }

    Ok(files)
}

fn main() {
    let dir_path = "C:\\Users\\mikke";
    match list_files(dir_path) {
        Ok(files) => {
            for file in files {
                let file_name = file.file_name();
                let file_name_str = file_name.to_string_lossy().into_owned();
                println!("{}", file_name_str);
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}