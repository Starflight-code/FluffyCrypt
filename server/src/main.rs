use diesel::{Connection, SqliteConnection};

mod models;
mod schema;

pub async fn establish_connection() -> SqliteConnection {
    let database_url = "./data.db";
    SqliteConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}
#[tokio::main]
async fn main() {
    println!("Hello, world!");
}
