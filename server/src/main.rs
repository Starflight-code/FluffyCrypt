use std::{net::SocketAddr, thread::sleep, time::Duration};

use diesel::{Connection, SqliteConnection};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream},
    spawn,
};

mod comms;
mod models;
mod schema;

use crate::comms::Message;

pub async fn establish_connection() -> SqliteConnection {
    let database_url = "./data.db";
    SqliteConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub async fn handle_connection(socket: TcpStream, addr: SocketAddr) {
    println!("Connection recieved from: {}", addr);
    loop {
        if socket.readable().await.is_ok() {
            let mut read_buff = vec![0; 1024];

            let len = socket.try_read(read_buff.as_mut_slice());
            if len.is_err() || len.as_ref().is_ok_and(|x| *x == 0) {
                sleep(Duration::from_millis(1));
                continue;
            }
            let len = len.unwrap();
            read_buff.truncate(len);

            dbg!(Message::from_req(&mut read_buff));
        }
    }
}

pub async fn connect_to_host() {
    sleep(Duration::from_secs(1));
    let to_tx: Vec<Vec<u8>> = vec![
        Message::RateReject().to_req(),
        Message::UcidReject(500).to_req(),
    ];
    // test - connect from another thread
    let addr = "127.0.0.1:4200".parse().unwrap();

    let socket = TcpSocket::new_v4().unwrap();
    let stream = socket.connect(addr).await.unwrap();

    for tx in to_tx {
        if stream.writable().await.is_ok() {
            println!("TX: {:?}", tx.as_slice());
            stream.try_write(tx.as_slice()).unwrap();
            sleep(Duration::from_millis(1));
        }
    }
}
#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:4200")
        .await
        .expect("Could not bind to port 4200");
    spawn(async move {
        connect_to_host().await;
    });
    loop {
        match listener.accept().await {
            Ok((socket, addr)) => handle_connection(socket, addr).await,
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    }
}
