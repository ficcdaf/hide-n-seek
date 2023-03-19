use chacha20poly1305::{
    aead::{stream, NewAead},
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::File,
    io::{Read, Write},
};
use anyhow::anyhow;
// Encryption code learned from Sylvain Kerkour
pub fn encrypt_file(
    source_path: &str,
    dest_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::create(dest_path)?;

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let cipher = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting file: {}", err))?;
            dest_file.write(&cipher)?;
        } else {
            let cipher = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting last segment of file: {}", err))?;
            dest_file.write(&cipher)?;
            break;
        }
    }

    Ok(())
}

pub fn decrypt_file(
    source_path: &str,
    dest_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());
    const BUFFER_LEN: usize = 516;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::create(dest_path)?;

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plain_text = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting file: {}", err))?;
            dest_file.write(&plain_text)?;
        } else if read_count == 0{
            break;
        } else {
            let plain_text = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting last segment of file: {}", err))?;
            dest_file.write(&plain_text)?;
            break;
        }
    }

    Ok(())
}

pub fn generate_key()
    -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    return key;
}

pub fn generate_nonce()
    -> [u8; 19] {
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut nonce);
    return nonce;
}
