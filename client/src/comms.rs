use rand::{self, Rng};
use std::time::{self, SystemTime};

const BITS_OF_TIME: u64 = 50;
const BITS_OF_RANDOM: u64 = 14;
const MAX_TIME: u64 = 2_u64.pow(BITS_OF_TIME as u32);
const MAX_RANDOM: u64 = 2_u64.pow(BITS_OF_RANDOM as u32);

/// generates snowflake id using unix millis (first `BITS_OF_TIME` bits) and `BITS_OF_RANDOM` random bits.
/// makes a total of 64 bits
pub(crate) fn generate_ucid() -> Result<u64, ()> {
    let timestamp = time::SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);

    if timestamp.is_err() {
        return Err(());
    }
    let timestamp = timestamp.unwrap().as_millis();
    if timestamp > MAX_TIME.into() {
        // if timestamp overflows beyond 50 bits, it can't be generated
        return Err(());
    }
    let mut timestamp = (timestamp as u64) << BITS_OF_RANDOM; // position timestamp on first 50 bits of u64
    timestamp += rand::thread_rng().gen_range(0..MAX_RANDOM); // fills in 14 bits of random

    return Ok(timestamp);
}

#[allow(dead_code)]
#[derive(Debug)]
/// contains both client & server messages
pub(crate) enum Message<'a> {
    /// client register (client send)
    RegisterClient((u64, &'a [u8])),

    /// client message reject (server send)
    UcidReject(u64),

    /// client message reject (server send)
    RateReject(),

    /// client message reject (server send)
    InvalidReq(),

    /// client message accepted (server send)
    Accepted(&'a [u8]),

    /// internal (parser generated, non-transmittable)
    Malformed(),
}

const NUMBER_OF_SEGMENTS: u64 = 8;

impl Message<'_> {
    /// constructs a u64 from an 8 element u8 array (maps first values to most significant bits and last to least significant bits)
    fn u64_from_u8_array(values: &[u8]) -> Result<u64, ()> {
        if values.len() != NUMBER_OF_SEGMENTS as usize {
            return Err(());
        }
        let mut uid: u64 = 0;
        for i in 0..NUMBER_OF_SEGMENTS as usize {
            uid +=
                u64::from(values[i]) << NUMBER_OF_SEGMENTS * ((NUMBER_OF_SEGMENTS - 1) - i as u64);
            // use bitwise shifts to build a u64 value from in order u8 values
        }
        return Ok(uid);
    }

    /// splits a u64 value into an 8 element u8 vector (8 bits per value, starting from most significant to least significant bits)
    fn u8_array_from_u64<'a>(values: u64) -> Vec<u8> {
        let mut uid = [0 as u8; NUMBER_OF_SEGMENTS as usize];
        for i in 0..NUMBER_OF_SEGMENTS as usize {
            uid[i] = (values >> NUMBER_OF_SEGMENTS * ((NUMBER_OF_SEGMENTS - 1) - i as u64)) as u8;
            // use bitwise shifts to seperate a u64 value into u8 values
        }
        return uid.to_vec();
    }

    /// deserializes bits into a Message object
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
            4 => {
                return Message::InvalidReq();
            }
            _ => {
                return Message::Malformed();
            }
        }
    }

    /// serializes a Message object to transmittable bits
    pub fn to_req<'a>(&self) -> Vec<u8> {
        let mut req = Vec::new();
        match self {
            Message::RegisterClient((id, secret)) => {
                // [0, 8 bits][id - 64 bits][secret 0 <= x bits < INF]
                req.push(0 as u8);
                req.append(&mut Self::u8_array_from_u64(*id));
                req.append(&mut secret.to_vec());
                return req;
            }
            Message::UcidReject(id) => {
                // [1, 8 bits][id - 64 bits]
                req.push(1 as u8);
                req.append(&mut Self::u8_array_from_u64(*id));
                return req;
            }
            Message::RateReject() => {
                // [2, 8 bits][id - 64 bits]
                req.push(2 as u8);
                return req;
            }
            Message::Accepted(signature) => {
                // [3, 8 bits][key_encrypted - 0 <= x bits < INF]
                req.push(3 as u8);
                req.append(&mut signature.to_vec());
                return req;
            }
            Message::InvalidReq() => {
                // [4, 8 bits]
                req.push(4 as u8);
                return req;
            }
            Message::Malformed() => return [].to_vec(),
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
            Message::RegisterClient((256, &[133, 007])).to_req(),
            vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 133, 007]
        );
    }
}
