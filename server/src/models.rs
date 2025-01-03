use diesel::{prelude::Associations, AsChangeset, Identifiable, Insertable, Queryable, Selectable};

use crate::schema::{asymmetric_key, client_key};

#[derive(Queryable, Selectable, Identifiable, Debug)]
#[diesel(table_name = crate::schema::asymmetric_key)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AsymmetricKey {
    pub id: i32,
    pub algo_metadata: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Associations, Queryable, Selectable, Identifiable, Debug)]
#[diesel(table_name = crate::schema::client_key)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
#[diesel(belongs_to(AsymmetricKey))]
pub struct ClientKey {
    pub id: i32,
    pub asymmetric_key_id: i32,
    pub ucid: i64,  // unique client identifier
    pub paid: bool, // whether to authorize transmission of key to decryptor
    pub encryption_key: Vec<u8>,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = asymmetric_key)]
pub struct NewAsymmetricKey<'a> {
    pub public_key: &'a [u8],
    pub private_key: &'a [u8],
    pub algo_metadata: &'a str,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = client_key)]
pub struct NewClientKey<'a> {
    pub asymmetric_key_id: i32,
    pub ucid: i64, // unique client identifier
    pub encryption_key: &'a [u8],
    pub paid: bool,
}
