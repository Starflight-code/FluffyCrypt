use std::{env, io, process::exit};

use tracing::{event, Level};

/// checks environment and confirms with user if files should be encrypted
pub(crate) fn should_disable_crypto() -> bool {
    let mut disable_cryptography = false;
    if Ok(String::from("TRUE")) == env::var("FLUFFYCRYPT_DEV") {
        event!(
            Level::WARN,
            "This host is a development environment, cryptographic operations will not be performed!"
        );
        disable_cryptography = true;
    }

    if Ok(String::from("TRUE")) != env::var("FLUFFYCRYPT_DEV")
        && Ok(String::from("TRUE")) != env::var("FLUFFYCRYPT_ALLOW_TARGET")
    {
        // if not development and not allowed
        event!(
            Level::ERROR,
            "This host has not been whitelisted. Fluffycrypt will now exit!"
        );
        exit(1);
    } else if Ok(String::from("TRUE")) == env::var("FLUFFYCRYPT_DEV")
        && Ok(String::from("TRUE")) == env::var("FLUFFYCRYPT_ALLOW_TARGET")
    {
        // if development and allowed
        event!(
            Level::WARN,
            "This host has been whitelisted and has noted itself as a development system. Cryptographic operations have been re-enabled."
        );
        disable_cryptography = false;
    }

    if !disable_cryptography {
        println!("Are you sure you'd like to nuke this system? ");
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        if input.to_lowercase() != *"yes" {
            disable_cryptography = true;
            event!(
                Level::WARN,
                "Cryptography disabled per user input. System will still perform all stages except the encryption stage."
            );
        }
    }
    disable_cryptography
}
