use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    net::SocketAddr,
    thread::sleep,
    time::{self, Duration, SystemTime},
};

use diesel::{
    dsl::insert_into, Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SqliteConnection,
};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use models::{AsymmetricKey, ClientKey, NewAsymmetricKey, NewClientKey};
use openssl::rsa::{Padding, Rsa};
use std::net::IpAddr::{V4, V6};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::comms::Message;

mod comms;
mod models;
mod schema;

/// diesel-rs migrations, automatically migrates DB on startup for easy deployment
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/");

/// SERVER IP, used for generating obfuscated `ip-port.bin` file
pub const SERVER_ADDRESS: &str = "127.0.0.1:4200";
pub const MAX_FAILURES: i32 = 3;

/// establishes connection with the local SQLite database, returns the connection
pub async fn establish_connection() -> SqliteConnection {
    let database_url = "./data.db";
    SqliteConnection::establish(database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

/// shifts a u64 to fit within a i64, by turing the number into a negative depending on the most significant bit value
fn shift_u64_to_i64(number: u64) -> i64 {
    if number >> 63 == 1 {
        // if MSB is negative, remove MSB and make the output negative
        -((number & !(1 << 63)) as i64)
    } else {
        number as i64
    }
}

#[allow(dead_code)]
fn ensure_snowflake_range(snowflake: u64, tolerance_millis: u64) -> bool {
    let now = time::SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    (now as i128 - (snowflake >> 14) as i128).abs() < tolerance_millis as i128
}

/// handles a `msg` recieved, sending responses to the provided `socket`
async fn handle_message(
    msg: Message<'_>,
    socket: &TcpStream,
    failures: &mut i32,
) -> Result<(), ()> {
    use crate::schema::asymmetric_key::dsl as asym_dsl;
    use crate::schema::client_key::dsl as client_dsl;
    let mut db = establish_connection().await;
    match msg {
        Message::RegisterClient(id, recieved_key) => {
            if (client_dsl::client_key
                .filter(client_dsl::ucid.eq(shift_u64_to_i64(id)))
                .first(&mut db) as Result<ClientKey, _>)
                .is_ok()
            {
                // if key is duplicate or snowflake time is not within 1000 ms of current time
                if socket.writable().await.is_ok() {
                    // key is a duplicate, send rejection
                    let _ = socket.try_write(&Message::UcidReject(id).to_req().to_vec());
                    *failures += 1;
                }
            } else {
                let decryption_key: AsymmetricKey =
                    asym_dsl::asymmetric_key.first(&mut db).unwrap();
                // fetch asymmetric key and decrypt message here
                let p_key =
                    openssl::rsa::Rsa::private_key_from_pem(&decryption_key.private_key).unwrap(); // swap key placeholder with database read
                let p_key = openssl::pkey::PKey::from_rsa(p_key).unwrap();
                let decryptor = openssl::encrypt::Decrypter::new(&p_key).unwrap();

                let buffer_len = decryptor.decrypt_len(recieved_key).unwrap();
                let mut decoded = vec![0u8; buffer_len];

                // Decrypt the data and get its length
                let decoded_len = decryptor.decrypt(recieved_key, &mut decoded).unwrap();

                // Use only the part of the buffer with the decrypted data
                let decoded = &decoded[..decoded_len];

                let record: NewClientKey = NewClientKey {
                    asymmetric_key_id: 1,
                    ucid: shift_u64_to_i64(id),
                    encryption_key: decoded,
                    paid: false,
                };
                if socket.writable().await.is_ok() && decoded.len() < 246 && decoded.len() > 266 {
                    let _ = socket.try_write(&Message::Malformed().to_req().to_vec());
                }
                insert_into(client_dsl::client_key)
                    .values(record)
                    .execute(&mut db)
                    .unwrap();
                if socket.writable().await.is_ok() {
                    // succeeded, accept the message
                    let _ = socket.try_write(&Message::Accepted(recieved_key).to_req().to_vec());
                }

                // this might produce the result we'd expect, I'll need to make sure it's decrypting with the private key
            }
            Ok(())
        }

        Message::RequestKey(ucid, transit_key) => {
            let key = client_dsl::client_key
                .filter(client_dsl::ucid.eq(shift_u64_to_i64(ucid)))
                .first(&mut db) as Result<ClientKey, _>;
            if key.is_err() || !key.as_ref().unwrap().paid {
                // if ucid was not registered or is not paid, reject and drop connection
                if socket.writable().await.is_ok() {
                    let _ = socket.try_write(&Message::Denied(ucid).to_req().to_vec());
                }
                println!(
                    "Recieved key request from {:?}, rejected.",
                    socket.peer_addr()
                );
                return Err(());
            }

            let p_key = openssl::rsa::Rsa::public_key_from_der(transit_key).unwrap(); // swap key placeholder with database read
            let p_key = openssl::pkey::PKey::from_rsa(p_key).unwrap();
            let encrypter = openssl::encrypt::Encrypter::new(&p_key).unwrap();

            let buffer_len = encrypter
                .encrypt_len(&key.as_ref().unwrap().encryption_key)
                .unwrap();
            let mut encrypted = vec![0u8; buffer_len];

            // Decrypt the data and get its length
            let _ = encrypter
                .encrypt(&key.unwrap().encryption_key, &mut encrypted)
                .unwrap();

            if socket.writable().await.is_ok() {
                let _ = socket.try_write(&Message::Approved(&encrypted).to_req().to_vec());
            }
            println!(
                "Recieved key request from {:?}, approved and transmitted decryption key.",
                socket.peer_addr()
            );
            Ok(())
        }

        // all other values are malformed (should not be sent to server), ignore them (verbose for protocol clarity)
        Message::UcidReject(_) => Err(()),
        Message::RateReject() => Err(()),
        Message::Accepted(_) => Err(()),
        Message::InvalidReq() => Err(()),
        Message::Malformed() => Err(()),
        Message::Denied(_) => Err(()),
        Message::Approved(_) => Err(()),
    }
}

/// handles a connection object, handles rate limited by checking `limit_map` for IP matches
async fn handle_connection(
    socket: TcpStream,
    addr: SocketAddr,
    limit_map: &mut HashMap<u128, u64>,
) {
    if !check_rate_limit(&addr, limit_map).await {
        println!("Connection recieved from: {} (Rejected, Rate Limit)", addr);
        if socket.writable().await.is_ok()
            && socket.try_write(&Message::RateReject().to_req()).is_err()
        {
            println!("Failed to write client reject response (timeout)");
        }
        return;
    }

    println!("Connection recieved from: {}", addr);

    let mut failures = 0;

    loop {
        let read_ready = socket.readable().await;
        if read_ready.is_ok() {
            let mut read_buff = vec![0; 1024];

            // read buffer, handle errors
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

            // parse network message, send to handler
            let msg = Message::from_req(&mut read_buff);
            if handle_message(msg, &socket, &mut failures).await.is_err() {
                return;
            }
        } else {
            sleep(Duration::from_millis(1));
        }
    }
}

/// connects to the local server, used for testing
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

/// writes the encrypted server IP & Port to the filesystem, uses `db` to lookup current key
async fn write_obfuscated_ip_port(db: &mut SqliteConnection) {
    use crate::schema::asymmetric_key::dsl as asym_dsl;

    // import key
    let key: AsymmetricKey = asym_dsl::asymmetric_key.first(db).unwrap();
    let rsa = openssl::rsa::Rsa::private_key_from_pem(key.private_key.as_slice()).unwrap();

    let mut buff = vec![0u8; rsa.size() as usize];
    let _ = rsa
        .private_encrypt(SERVER_ADDRESS.as_bytes(), &mut buff, Padding::PKCS1)
        .unwrap();

    // encrypt & print
    let mut output = File::create("ip-port.bin").unwrap();
    output.write_all(buff.as_slice()).unwrap();
}

/// checks if the address has been used in the last 30 seconds
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
        if let Some(timestamp) = limit_map.insert(ip.to_bits(), since_epoch) {
            if timestamp + 30 > since_epoch {
                return false;
            }
        }
    }
    true
}

/// generates an RSA key and writes it to the database
async fn generate_and_write_key(db: &mut SqliteConnection) {
    use crate::schema::asymmetric_key::dsl as asym_dsl;

    // generate key
    let key = Rsa::generate(4096).unwrap();

    // save to DB
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
    write_obfuscated_ip_port(&mut db).await;

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
        assert_eq!(shift_u64_to_i64(0), 0);
    }

    #[test]
    fn test_value_shift_2() {
        assert_eq!(shift_u64_to_i64(u64::MAX / 2), i64::MAX);
    }

    #[test]
    fn test_value_shift_3() {
        assert_eq!(shift_u64_to_i64(u64::MAX), i64::MIN + 1);
    }

    #[test]
    fn test_value_shift_4() {
        // 1000...0001 should convert to an negative i64 equal to its value without the most significant bit, but negative
        assert_eq!(shift_u64_to_i64(1 + (1_u64 << 63)), -1);
    }
}
