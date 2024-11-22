// @generated automatically by Diesel CLI.

diesel::table! {
    asymmetric_key (id) {
        id -> Integer,
        algo_metadata -> Text,
        public_key -> Binary,
        private_key -> Binary,
    }
}

diesel::table! {
    client_key (id) {
        id -> Integer,
        asymmetric_key_id -> Integer,
        ucid -> BigInt,
        paid -> Bool,
        encryption_key -> Binary,
    }
}

diesel::joinable!(client_key -> asymmetric_key (asymmetric_key_id));

diesel::allow_tables_to_appear_in_same_query!(
    asymmetric_key,
    client_key,
);
