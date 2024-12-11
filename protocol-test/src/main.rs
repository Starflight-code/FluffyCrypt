use std::{thread::sleep, time::Duration};

use comms::Message;
use tokio::net::TcpSocket;
mod comms;

#[allow(dead_code)]
async fn connect_to_host<'a>(delay: i32, to_tx: Vec<Message<'a>>)
{
    sleep(Duration::from_secs(delay.try_into().unwrap()));
    
    // test - connect from another thread
    let addr = "127.0.0.1:4200".parse().unwrap();

    let socket = TcpSocket::new_v4().unwrap();
    let stream = socket.connect(addr).await.unwrap();

    for tx in to_tx {
        if stream.writable().await.is_ok() {
            println!("TX: {:?}", tx);
            let _ = stream.try_write(tx.to_req().as_slice());
            sleep(Duration::from_millis(1));
        }
    }
}

fn main() {
}
