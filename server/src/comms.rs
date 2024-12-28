use tracing::{event, Level};

#[allow(dead_code)]
#[derive(Debug)]
/// contains both client & server messages
pub(crate) enum Message<'a> {
    /// client register (client send)
    RegisterClient(u64, &'a [u8]),

    /// client message reject (server send)
    UcidReject(u64),

    /// client message reject (server send)
    RateReject(),

    /// client message reject (server send)
    InvalidReq(),

    /// client message accepted (server send)
    Accepted(&'a [u8]),

    /// client request key (client send)
    RequestKey(u64, &'a [u8]),

    /// client request denied (server send)
    Denied(u64),

    /// client request approved (server send)
    Approved(&'a [u8]),

    /// internal (parser generated, non-transmittable)
    Malformed(),
}

const NUMBER_OF_SEGMENTS: u64 = 8;

#[allow(clippy::needless_range_loop)]
impl Message<'_> {
    /// constructs a u64 from an 8 element u8 array (maps first values to most significant bits and last to least significant bits)
    fn u64_from_u8_array(values: &[u8]) -> Result<u64, ()> {
        if values.len() != NUMBER_OF_SEGMENTS as usize {
            return Err(());
        }
        let mut uid: u64 = 0;
        for i in 0..NUMBER_OF_SEGMENTS as usize {
            uid += u64::from(values[i])
                << (NUMBER_OF_SEGMENTS * ((NUMBER_OF_SEGMENTS - 1) - i as u64));
            // use bitwise shifts to build a u64 value from in order u8 values
        }
        Ok(uid)
    }

    /// splits a u64 value into an 8 element u8 vector (8 bits per value, starting from most significant to least significant bits)
    fn u8_array_from_u64(values: u64) -> Vec<u8> {
        let mut uid = [0_u8; NUMBER_OF_SEGMENTS as usize];
        for i in 0..NUMBER_OF_SEGMENTS as usize {
            uid[i] = (values >> (NUMBER_OF_SEGMENTS * ((NUMBER_OF_SEGMENTS - 1) - i as u64))) as u8;
            // use bitwise shifts to seperate a u64 value into u8 values
        }
        uid.to_vec()
    }

    /// deserializes bits into a Message object
    pub fn from_req(network_msg: &mut [u8]) -> Message {
        if network_msg.is_empty() {
            event!(
                Level::TRACE,
                "Network message was empty, marking as malformed."
            );
            return Message::Malformed();
        }

        match network_msg[0] {
            0 => {
                if network_msg.len() <= 9 {
                    event!(
                        Level::TRACE,
                        "Network message (Register Client) was too short ({}), marking as malformed.", 
                        network_msg.len()
                    );
                    // allows 1-any byte keys, change once key size has been determined
                    return Message::Malformed();
                }
                Message::RegisterClient(
                    Self::u64_from_u8_array(&network_msg[1..9]).unwrap(),
                    &network_msg[9..network_msg.len()],
                )
            }
            1 => {
                if network_msg.len() < 9 {
                    event!(
                        Level::TRACE,
                        "Network message (UcidReject) was too short ({}), marking as malformed.",
                        network_msg.len()
                    );
                    return Message::Malformed();
                }
                Message::UcidReject(Self::u64_from_u8_array(&network_msg[1..9]).unwrap())
            }
            2 => Message::RateReject(),
            3 => {
                if network_msg.len() <= 1 {
                    event!(
                        Level::TRACE,
                        "Network message (Accepted) was too short ({}), marking as malformed.",
                        network_msg.len()
                    );
                    // allows 1-any byte keys, change once key size has been determined
                    return Message::Malformed();
                }
                Message::Accepted(&network_msg[1..network_msg.len()])
            }
            4 => Message::InvalidReq(),
            5 => {
                if network_msg.len() <= 9 {
                    event!(
                        Level::TRACE,
                        "Network message (RequestKey) was too short ({}), marking as malformed.",
                        network_msg.len()
                    );
                    return Message::Malformed();
                }
                Message::RequestKey(
                    Self::u64_from_u8_array(&network_msg[1..9]).unwrap(),
                    &network_msg[9..network_msg.len()],
                )
            }
            6 => {
                if network_msg.len() < 9 {
                    event!(
                        Level::TRACE,
                        "Network message (Denied) was too short ({}), marking as malformed.",
                        network_msg.len()
                    );
                    return Message::Malformed();
                }
                Message::Denied(Self::u64_from_u8_array(&network_msg[1..9]).unwrap())
            }
            7 => {
                if network_msg.len() <= 1 {
                    event!(
                        Level::TRACE,
                        "Network message (Approved) was too short ({}), marking as malformed.",
                        network_msg.len()
                    );
                    return Message::Malformed();
                }
                Message::Approved(&network_msg[1..network_msg.len()])
            }
            _ => Message::Malformed(),
        }
    }

    /// serializes a Message object to transmittable bits
    pub fn to_req(&self) -> Vec<u8> {
        let mut req = Vec::new();
        match self {
            Message::RegisterClient(id, secret) => {
                // [0, 8 bits][id - 64 bits][secret 246 <= x bits <= 266]
                req.push(0_u8);
                req.append(&mut Self::u8_array_from_u64(*id));
                req.append(&mut secret.to_vec());
                req
            }
            Message::UcidReject(id) => {
                // [1, 8 bits][id - 64 bits]
                req.push(1_u8);
                req.append(&mut Self::u8_array_from_u64(*id));
                req
            }
            Message::RateReject() => {
                // [2, 8 bits][id - 64 bits]
                req.push(2_u8);
                req
            }
            Message::Accepted(signature) => {
                // [3, 8 bits][signature - 246 <= x bits <= 266]
                req.push(3_u8);
                req.append(&mut signature.to_vec());
                req
            }
            Message::InvalidReq() => {
                // [4, 8 bits]
                req.push(4_u8);
                req
            }
            Message::RequestKey(id, client_pkey) => {
                // [5, 8 bits][id - 64 bits][client_pkey - 246 <= x bits <= 266]
                req.push(5_u8);
                req.append(&mut Self::u8_array_from_u64(*id));
                req.append(&mut client_pkey.to_vec());
                req
            }
            Message::Denied(id) => {
                // [6, 8 bits][id - 64 bits]
                req.push(6_u8);
                req.append(&mut Self::u8_array_from_u64(*id));
                req
            }
            Message::Approved(encapsulated_key) => {
                // [7, 8 bits][key_encrypted - 246 <= x bits <= 266]
                req.push(7_u8);
                req.append(&mut encapsulated_key.to_vec());
                req
            }
            Message::Malformed() => [].to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::u64;

    use super::*;

    #[test]
    fn test_networkize_1() {
        assert_eq!(
            Message::UcidReject(u64::MAX).to_req(),
            vec![1, 255, 255, 255, 255, 255, 255, 255, 255]
        );
    }

    #[test]
    fn test_networkize_2() {
        assert_eq!(
            Message::Accepted(&[0, 0, 0, 0]).to_req(),
            vec![3, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_networkize_3() {
        assert_eq!(Message::Malformed().to_req(), vec![]);
    }

    #[test]
    fn test_networkize_4() {
        assert_eq!(Message::RateReject().to_req(), vec![2]);
    }

    #[test]
    fn test_networkize_5() {
        assert_eq!(
            Message::RegisterClient(256, &[133, 7]).to_req(),
            vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 133, 7]
        );
    }

    #[test]
    fn test_networkize_6() {
        assert_eq!(
            Message::RequestKey(256, &[133, 7]).to_req(),
            vec![5, 0, 0, 0, 0, 0, 0, 1, 0, 133, 7]
        );
    }

    #[test]
    fn test_networkize_7() {
        assert_eq!(
            Message::Denied(256).to_req(),
            vec![6, 0, 0, 0, 0, 0, 0, 1, 0]
        );
    }

    #[test]
    fn test_networkize_8() {
        assert_eq!(Message::Approved(&[133, 7]).to_req(), vec![7, 133, 7]);
    }
}
