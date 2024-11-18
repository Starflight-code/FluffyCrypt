use std::{
    collections::HashMap,
    net::SocketAddr,
    thread::sleep,
    time::{Duration, SystemTime},
};

use diesel::{Connection, SqliteConnection};
use std::net::IpAddr::{V4, V6};
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

pub async fn handle_connection(
    socket: TcpStream,
    addr: SocketAddr,
    limit_map: &mut HashMap<u128, u64>,
) {
    if !check_rate_limit(&addr, limit_map).await {
        println!("Connection recieved from: {} (Rejected, Rate Limit)", addr);
        if socket.writable().await.is_ok() {
            if let Err(_) = socket.try_write(&Message::RateReject().to_req()) {
                println!("Failed to write client reject response (timeout)");
            }
        }
        return;
    }
    println!("Connection recieved from: {}", addr);
    loop {
        let read_ready = socket.readable().await;
        if read_ready.is_ok() {
            let mut read_buff = vec![0; 1024];

            let len = socket.try_read(read_buff.as_mut_slice());
            if len.is_err() {
                sleep(Duration::from_millis(1));
                continue;
            } else if len.as_ref().is_ok_and(|x| *x == 0) {
                println!("Connection dropped by {}", addr);
                return;
            }
            let len = len.unwrap();
            read_buff.truncate(len);

            dbg!(Message::from_req(&mut read_buff));
        } else {
            println!("Connection Error: Disconnecting from {}", addr);
            return;
        }
    }
}

pub async fn connect_to_host(delay: i32) {
    sleep(Duration::from_secs(delay.try_into().unwrap()));
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

pub async fn check_rate_limit(addr: &SocketAddr, limit_map: &mut HashMap<u128, u64>) -> bool {
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH + Duration::from_secs(1704067200))
        .unwrap()
        .as_secs();
    if let V4(ip) = addr.ip() {
        if let Some(timestamp) = limit_map.insert(ip.to_bits() as u128, since_epoch) {
            if timestamp + 30 > since_epoch {
                return false;
            }
        }
    }
    if let V6(ip) = addr.ip() {
        if let Some(timestamp) = limit_map.insert(ip.to_bits() as u128, since_epoch) {
            if timestamp + 30 > since_epoch {
                return false;
            }
        }
    }
    return true;
}
#[tokio::main]
async fn main() {
    let mut limit_map: HashMap<u128, u64> = HashMap::new();
    let listener = TcpListener::bind("127.0.0.1:4200")
        .await
        .expect("Could not bind to port 4200");
    spawn(async move {
        connect_to_host(1).await;
    });
    spawn(async move {
        connect_to_host(2).await;
    });
    spawn(async move {
        connect_to_host(2).await;
    });
    loop {
        match listener.accept().await {
            Ok((socket, addr)) => handle_connection(socket, addr, &mut limit_map).await,
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    }
}
