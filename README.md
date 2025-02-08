# FluffyCrypt
[![Rust](https://github.com/Starflight-code/FluffyCrypt/actions/workflows/rust.yml/badge.svg)](https://github.com/Starflight-code/FluffyCrypt/actions/workflows/rust.yml)
<p align="center">
  <img src="https://github.com/user-attachments/assets/d0f5ea9e-9940-4ba6-a716-1a12a9a79111" width=40% height=40%>
</p>

FluffyCrypt should be used for educational purposes only. Safeguards have been put in place to prevent unauthorized use of this program, please DO NOT remove these safeguards.

FluffyCrypt is Ransomware created as part of a Computer Science class. This program enumerates the user's home directory and uses OpenSSL to encrypt all contained files. After encrypting files, it generates an identifier and transmits the key to a server component. This server will hold on to the key until the paid flag is marked within the SQLite Database. After this flag is marked, the client will be able to send a KeyRequest packet with an RSA public key. An RSA enveloped AES key corresponding to their key (identified by their registered UCID) will be transmitted back. Decryption can then proceed automatically. Encryption is used for all key transmission.

To run the client program with encryption enabled, you must enable set FLUFFYCRYPT_ALLOW_TARGET=TRUE. Note: if this program is executed on a computer without a server running (or the targeted server is inaccessable), the files will be irrecoverable. Set the FLUFFYCRYPT_DEV=TRUE environment variable to enable the system with a tracing log level, you can unset the FLUFFYCRYPT_ALLOW_TARGET=TRUE to run the program with cryptography disabled.

<p align="center">
  <img src="https://github.com/user-attachments/assets/4de96513-bbaf-410c-80cd-38d1d921a272">
</p>

## How do I get started?

Start by cloning this repo and enter the repo's folder. Then run the server and client.
1. cd server
2. cargo run -r
3. -- Open a new terminal --
4. cd client
5. export FLUFFYCRYPT_DEV=TRUE
6. cargo run -r

The client and server are now running. Since we've only set dev mode, there's no risk of encrypting all your files (unless you're using a modified version of FluffyCrypt). Make sure to check over the source code to make sure everything looks right if you're unsure (this program isn't very large, probably <3 KLOC).
