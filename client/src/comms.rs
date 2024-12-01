use rand::{self, Rng};
use std::time::{self, SystemTime};

pub(crate) fn generate_ucid() -> Result<u64, ()> {
    let timestamp = time::SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);

    if timestamp.is_err() {
        return Err(());
    }
    let timestamp = timestamp.unwrap().as_millis();
    if timestamp > 2 ^ 50 {
        // if timestamp overflows beyond 50 bits, it can't be generated
        return Err(());
    }
    let mut timestamp = (timestamp as u64) << 14; // position timestamp on first 50 bits of u64
    timestamp += rand::thread_rng().gen_range(0..2 ^ 16); // fills in 14 bits of random

    return Ok(timestamp);
}

#[derive(Debug)]
pub(crate) enum Message<'a> {
    // contains both client & server commands
    RegisterClient((u64, &'a [u8])),
    UcidReject(u64),
    RateReject(),
    InvalidReq(),
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
            4 => {
                return Message::InvalidReq();
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
                req.push(3 as u8);
                req.append(&mut signature.to_vec());
                return req;
            }
            Message::InvalidReq() => {
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
