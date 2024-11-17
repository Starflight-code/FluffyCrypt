// @generated automatically by Diesel CLI.

diesel::table! {
    asymmetric_key (id) {
        id -> Integer,
        public_key -> Text,
        private_key -> Text,
        algo_metadata -> Text,
    }
}

diesel::table! {
    client_key (id) {
        id -> Integer,
        asymmetric_key_id -> Integer,
        ucid -> BigInt,
        encryption_key -> Text,
        paid -> Bool,
    }
}

diesel::joinable!(client_key -> asymmetric_key (asymmetric_key_id));

diesel::allow_tables_to_appear_in_same_query!(
    asymmetric_key,
    client_key,
);
