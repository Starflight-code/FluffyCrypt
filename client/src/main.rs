use tokio::fs::{ DirEntry, read_dir };
use tokio::task;
use std::io;
use std::path::Path;

async fn list_files(dir_path: &str) -> io::Result<Vec<DirEntry>> {
    let mut files: Vec<DirEntry> = Vec::new();
    let mut entries = read_dir(Path::new(dir_path)).await?;

    while let Some(entry) = entries.next_entry().await? {
        files.push(entry);
    }

    Ok(files)
}

#[tokio::main]
async fn main() {
    let dir_path = "C:\\Users\\mikke";
    match list_files(dir_path).await {
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
