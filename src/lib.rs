use openssl::error::ErrorStack;
use openssl::pkey::{Private, Public};
use openssl::rsa::{Padding, Rsa};

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

pub struct RsaCrypto {}

impl RsaCrypto {
    pub fn load_priv_key(priv_str: &str) -> Result<Rsa<Private>, ErrorStack> {
        let priv_key_pem: String = Self::format_pem("PRIVATE", priv_str);
        Rsa::private_key_from_pem(priv_key_pem.as_bytes())
    }

    pub fn load_pub_key(pub_str: &str) -> Result<Rsa<Public>, ErrorStack> {
        let pub_key_pem: String = Self::format_pem("PUBLIC", pub_str);
        Rsa::public_key_from_pem(pub_key_pem.as_bytes())
    }

    fn format_pem(key_type: &str, key_data: &str) -> String {
        let header = format!("-----BEGIN {} KEY-----\n", key_type);
        let footer = format!("-----END {} KEY-----\n", key_type);
        let mut pem = String::new();

        pem.push_str(&header);

        for chunk in key_data.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }

        pem.push_str(&footer);
        pem
    }

    pub fn encrypt_with_priv_key(priv_key: &Rsa<Private>, data: &[u8]) -> String {
        let mut result = Vec::<u8>::new();
        let buff_size = priv_key.size() as usize;
        let mut buf = vec![0; buff_size];
        let mut start: usize = 0;

        //if use Padding::PKCS1 =>encrypt length = key length - 11
        //if use Padding::OAEP  =>encrypt length = key length - 42
        let max_encrypt_block = buff_size - 11;
        //println!("max_encrypt_block:{}", max_encrypt_block);
        let mut end = start + max_encrypt_block;
        if end > data.len() {
            end = data.len();
        }

        loop {
            if start >= data.len() {
                // println!("start:{} >= data.len():{}", start, data.len());
                break;
            }

            let ret: Result<usize, ErrorStack> =
                priv_key.private_encrypt(&data[start..end], &mut buf, Padding::PKCS1);
            match ret {
                Ok(size) => {
                    result.extend_from_slice(&buf[0..size]);
                    start += max_encrypt_block;
                    end += max_encrypt_block;
                    if end > data.len() {
                        end = data.len();
                    }
                }
                Err(e) => {
                    result.clear();
                    panic!("encrypt_with_priv_key error:{}", e)
                }
            }
        }
        if result.len() == 0 {
            String::new()
        } else {
            base64_url::encode(&result)
        }
    }

    pub fn decrypt_with_pub_key(pub_key: &Rsa<Public>, data: &[u8]) -> String {
        let data = match base64_url::decode(data) {
            Ok(v) => v,
            Err(e) => {
                panic!("decrypt_with_pub_key base64_url decode error:{}", e)
            }
        };

        let mut result = Vec::<u8>::new();
        let buff_size = pub_key.size() as usize;
        let mut buf = vec![0; buff_size];
        let mut start: usize = 0;
        let mut end: usize = data.len();
        let max_decrypt_block = buff_size;
        //println!("max_decrypt_block:{}", max_decrypt_block);

        if end > max_decrypt_block {
            end = max_decrypt_block;
        }

        loop {
            if start >= data.len() {
                break;
            }
            let ret = pub_key.public_decrypt(&data[start..end], &mut buf, Padding::PKCS1);
            match ret {
                Ok(size) => {
                    result.extend_from_slice(&buf[0..size]);

                    start += max_decrypt_block;
                    end += max_decrypt_block;

                    if end > data.len() {
                        end = data.len();
                    }
                }
                Err(e) => {
                    result.clear();
                    panic!("decrypt_with_pub_key error:{}", e)
                }
            }
        }

        if result.len() == 0 {
            String::new()
        } else {
            String::from_utf8_lossy(&result).into_owned()
        }
    }
}

#[pyfunction]
fn private_key_encrypt(priv_str: &str, data: &str) -> PyResult<String> {
    let priv_key: Rsa<Private> = match RsaCrypto::load_priv_key(priv_str) {
        Ok(v) => v,
        Err(e) => {
            panic!("load_private_key error:{}", e)
        }
    };
    let encrypt_data = RsaCrypto::encrypt_with_priv_key(&priv_key, data.as_bytes());
    Ok(encrypt_data)
}

#[pyfunction]
fn public_key_decrypt(pub_str: &str, data: &str) -> PyResult<String> {
    let pub_key: Rsa<Public> = match RsaCrypto::load_pub_key(pub_str) {
        Ok(v) => v,
        Err(e) => {
            panic!("load_pub_key error:{}", e)
        }
    };
    let decrypt_data = RsaCrypto::decrypt_with_pub_key(&pub_key, data.as_bytes());
    Ok(decrypt_data)
}

#[pymodule]
fn custody_rsa(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(public_key_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(private_key_encrypt, m)?)?;
    Ok(())
}
