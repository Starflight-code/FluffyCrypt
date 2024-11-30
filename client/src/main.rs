#[cfg(unix)]
const PUB_KEY: &[u8] = include_bytes!("../pub.key");

#[cfg(windows)]
const PUB_KEY: &[u8] = include_bytes!("..\\pub.key");

#[tokio::main]
async fn main() {
    println!("Hello, world!");
}
