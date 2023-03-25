fn main() {
    let key = hide_n_seek::generate_key();
    let nonce = hide_n_seek::generate_nonce();
    println!("Encrypting file with key: {:?}", key);

    hide_n_seek::encrypt_file(
        "/home/isa/hide-n-seek/text.txt",
        "/home/isa/hide-n-seek/text.enc",
        &key,
        &nonce,
    )
    .unwrap();

    println!("Decrypting file with key: {:?}", key);

    hide_n_seek::decrypt_file(
        "/home/isa/hide-n-seek/text.enc",
        "/home/isa/hide-n-seek/text_dec.txt",
        &key,
        &nonce,
    )
    .unwrap();
}
