use crypto_box::{aead::OsRng, PublicKey};
use std::process;
use std::{
    fs::OpenOptions,
    io::{Error, Write},
};

pub fn log_data(message: String) {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("C:\\windows\\temp\\log.txt")
        .unwrap();

    file.write_all(message.as_bytes()).unwrap();
}

use chrono::Local;

pub trait Data {
    fn get_vec_from_data(&self) -> Vec<u8>;
}

impl Data for &Vec<u8> {
    fn get_vec_from_data(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Data for &Vec<u16> {
    fn get_vec_from_data(&self) -> Vec<u8> {
        let prefix: Vec<u16> = format!("({}) ", Local::now().format("%Y/%m/%d %H:%M:%S"))
            .encode_utf16()
            .collect();

        let data = [prefix, self.to_vec()].concat();
        let data_vec: &[u8] = unsafe { data.align_to::<u8>().1 };

        data_vec.to_vec()
    }
}

pub fn encrypt_and_log_data_to_file<T: Data>(
    file_path: String,
    data: T,
    public_key: &[u8; 32],
) -> Result<(), Error> {
    let mut path = file_path;
    path.push_str(&format!("{}.log", process::id()));

    let pk = PublicKey::from_bytes(*public_key);

    let data_slice = data.get_vec_from_data();

    let ciphertext = pk.seal(&mut OsRng, &data_slice).unwrap();

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(path)?;

    write!(&mut file, "---BEGIN---")?;
    file.write_all(&ciphertext)?;
    write!(&mut file, "---END---")?;

    Ok(())
}

#[cfg(test)]
mod tests {}
