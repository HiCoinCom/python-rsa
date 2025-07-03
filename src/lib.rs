use openssl::error::ErrorStack;
use openssl::pkey::{Private, Public};
use openssl::rsa::{Padding, Rsa};

use std::ffi::c_char;
use std::ffi::CStr;
use std::ffi::CString;

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
                    println!("encrypt_with_priv_key error:{}", e);
                    return String::new();
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
                println!("decrypt_with_pub_key base64_url decode error:{}", e);
                return String::new();
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
                    println!("decrypt_with_pub_key error:{}", e);
                    return String::new();
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

#[no_mangle]
pub extern "C" fn free_c_char(ptr: *mut c_char) {
    unsafe { drop(CString::from_raw(ptr)) };
}

#[no_mangle]
pub extern "C" fn private_key_encrypt(
    priv_str: *const c_char,
    data: *const c_char,
) -> *const c_char {
    let go_priv = unsafe {
        assert!(!priv_str.is_null());
        CStr::from_ptr(priv_str)
    };

    let go_priv_str = match go_priv.to_str() {
        Ok(v) => v,
        Err(e) => {
            println!("parse private key err: {}", e);
            return std::ptr::null();
        }
    };

    let priv_key: Rsa<Private> = match RsaCrypto::load_priv_key(go_priv_str) {
        Ok(v) => v,
        Err(e) => {
            println!("load_private_key error:{}", e);
            return std::ptr::null();
        }
    };

    let go_data = unsafe {
        assert!(!data.is_null());
        CStr::from_ptr(data)
    };

    let go_data_str = match go_data.to_str() {
        Ok(v) => v,
        Err(e) => {
            println!("parse data err: {}", e);
            return std::ptr::null();
        }
    };
    let encrypt_data = RsaCrypto::encrypt_with_priv_key(&priv_key, go_data_str.as_bytes());
    if encrypt_data.is_empty() {
        return std::ptr::null();
    }
    CString::new(encrypt_data).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn public_key_decrypt(pub_str: *const c_char, data: *const c_char) -> *const c_char {
    let go_pub = unsafe {
        assert!(!pub_str.is_null());
        CStr::from_ptr(pub_str)
    };

    let go_pub_str = match go_pub.to_str() {
        Ok(v) => v,
        Err(e) => {
            println!("parse public key err: {}", e);
            return std::ptr::null();
        }
    };

    let pub_key: Rsa<Public> = match RsaCrypto::load_pub_key(go_pub_str) {
        Ok(v) => v,
        Err(e) => {
            println!("load_pub_key error:{}", e);
            return std::ptr::null();
        }
    };

    let go_data = unsafe {
        assert!(!data.is_null());
        CStr::from_ptr(data)
    };

    let go_data_str = match go_data.to_str() {
        Ok(v) => v,
        Err(e) => {
            println!("parse encrypt data err: {}", e);
            return std::ptr::null();
        }
    };
    let decrypt_data = RsaCrypto::decrypt_with_pub_key(&pub_key, go_data_str.as_bytes());
    if decrypt_data.is_empty() {
        return std::ptr::null();
    }
    CString::new(decrypt_data).unwrap().into_raw()
}
