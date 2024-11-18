use std::{net::SocketAddr, thread::sleep, time::Duration};

use diesel::{Connection, SqliteConnection};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream},
    spawn,
};

mod models;
mod schema;

#[derive(Debug)]
enum Message<'a> {
    // contains both client & server commands
    RegisterClient((u64, &'a [u8])),
    UcidReject(u64),
    RateReject(),
    Accepted(&'a [u8]),
    Malformed(),
}

impl Message<'_> {
    fn u64_from_u8_array(values: &[u8]) -> Result<u64, ()> {
        if values.len() != 8 {
            return Err(());
        }
        let mut uid: u64 = 0;
        for i in 0..8 {
            uid += u64::from(values[i]) << 8 * (7 - i); // use bitwise shifts to build a u64 value from in order u8 values
        }
        return Ok(uid);
    }

    fn u8_array_from_u64<'a>(values: u64) -> Vec<u8> {
        let mut uid = [0 as u8; 8];
        for i in 0..8 {
            uid[i] = (values >> 8 * (7 - i)) as u8; // use bitwise shifts to seperate a u64 value into u8 values
        }
        return uid.to_vec();
    }
    pub fn from_req(network_msg: &mut [u8]) -> Message {
        if network_msg.len() == 0 {
            return Message::Malformed();
        }

        match network_msg[0] {
            0 => {
                if network_msg.len() <= 9 {
                    // allows 1-any byte keys, change once key size has been determined
                    return Message::Malformed();
                }
                return Message::RegisterClient((
                    Self::u64_from_u8_array(&network_msg[1..9]).unwrap(),
                    &network_msg[9..network_msg.len()],
                ));
            }
            1 => {
                if network_msg.len() < 9 {
                    return Message::Malformed();
                }
                return Message::UcidReject(Self::u64_from_u8_array(&network_msg[1..9]).unwrap());
            }
            2 => {
                return Message::RateReject();
            }
            3 => {
                if network_msg.len() <= 1 {
                    // allows 1-any byte keys, change once key size has been determined
                    return Message::Malformed();
                }
                return Message::Accepted(&network_msg[1..network_msg.len()]);
            }
            _ => {
                return Message::Malformed();
            }
        }
    }

    pub fn to_req<'a>(&self) -> Vec<u8> {
        let mut req = Vec::new();
        match self {
            Message::RegisterClient((id, secret)) => {
                req.push(0 as u8);
                req.append(&mut Self::u8_array_from_u64(*id));
                req.append(&mut secret.to_vec());
                return req;
            }
            Message::UcidReject(id) => {
                req.push(1 as u8);
                req.append(&mut Self::u8_array_from_u64(*id));
                return req;
            }
            Message::RateReject() => {
                req.push(2 as u8);
                return req;
            }
            Message::Accepted(signature) => {
                req.push(1 as u8);
                req.append(&mut signature.to_vec());
                return req;
            }
            Message::Malformed() => return [].to_vec(),
        }
    }
}

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
