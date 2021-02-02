use arrayref::array_ref;
use base64::encode;
use chrono::Utc;
use hex;
use num::bigint::ToBigUint;
use num::{BigInt, BigUint};
use rand::prelude::*;
use ring;
use std::collections::HashMap;

const N_HEX: &'static str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
const G_HEX: &'static str = "2";
const INFO_BITS: &'static str = "Caldera Derived Key";

// We define our type for testing, so we can swap between both types easily
type BigNum = BigInt;

fn hash_sha256(buf: &[u8]) -> String {
    let sha = ring::digest::digest(&ring::digest::SHA256, buf);
    format!("{:064}", hex::encode(sha.as_ref()))
}

fn hex_hash(hex_str: String) -> String {
    let bytes = hex::decode(hex_str).expect("Invalid hex_str provided in hex_hash");
    hash_sha256(&bytes)
}

fn hex_to_big(hex_str: String) -> BigNum {
    BigNum::parse_bytes(hex_str.as_bytes(), 16).expect("Error parsing hex_str in hex_to_big")
}

fn big_to_hex(big: BigNum) -> String {
    big.to_str_radix(16)
}

fn get_random(num_bytes: usize) -> BigNum {
    let mut rand_vec: Vec<u8> = vec![0; num_bytes];
    thread_rng().fill(rand_vec.as_mut_slice());
    BigNum::from_bytes_be(num::bigint::Sign::Plus, &rand_vec)
}

fn pad_hex_big(input: BigNum) -> String {
    let string = big_to_hex(input);
    pad_hex_string(string)
}

fn pad_hex_string(input: String) -> String {
    if input.len() % 2 == 1 {
        format!("0{}", input)
    } else if let Some(_) = "89ABCDEFabcdef".find(
        input
            .chars()
            .nth(0)
            .expect("Zero length string in pad_hex_string"),
    ) {
        format!("00{}", input)
    } else {
        input
    }
}

// Tested working
fn compute_hkdf(ikm: &[u8], salt: &[u8]) -> [u8; 16] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, salt);

    let tag = ring::hmac::sign(&key, ikm);

    let info_bits_update = format!("{}\x01", INFO_BITS);

    let final_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, tag.as_ref());

    let final_tag = ring::hmac::sign(&final_key, info_bits_update.as_bytes());

    array_ref!(final_tag.as_ref(), 0, 16).clone()
}

// Tested working
fn calculate_u(srp_a: BigNum, srp_b: BigNum) -> BigNum {
    let u_hex_hash = hex_hash(format!("{}{}", pad_hex_big(srp_a), pad_hex_big(srp_b)));
    hex_to_big(u_hex_hash)
}

#[derive(Debug, Clone)]
pub struct AwsSrpHelper {
    username: String,
    password: String,
    cognito_user_pool_id: String,
    client_id: String,
    client_secret: String,
    big_n: BigNum,
    val_g: BigNum,
    val_k: BigNum,
    small_a: BigNum,
    big_a: BigNum,
}

impl AwsSrpHelper {
    pub fn new(
        username: String,
        password: String,
        cognito_user_pool_id: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        let big_n = hex_to_big(N_HEX.into());
        let val_g = hex_to_big(G_HEX.into());
        let val_k = hex_to_big(hex_hash(format!("00{}0{}", N_HEX, G_HEX)));

        let mut partial_helper = AwsSrpHelper {
            username,
            password,
            cognito_user_pool_id,
            client_id,
            client_secret,
            big_n,
            val_g,
            val_k,
            small_a: BigNum::from(0u32),
            big_a: BigNum::from(0u32),
        };

        partial_helper.small_a = partial_helper.generate_random_small_a();
        partial_helper.big_a = partial_helper.calculate_a();

        partial_helper
    }

    // Seems to be working
    fn generate_random_small_a(&self) -> BigNum {
        let rand_big = get_random(128);
        &rand_big % &self.big_n
    }

    // Seems to be working
    fn calculate_a(&self) -> BigNum {
        let big_a = self.val_g.modpow(&self.small_a, &self.big_n);

        if &big_a % &self.big_n == BigNum::from(0u32) {
            panic!("Safety check for A failed!");
        }

        big_a
    }

    // Seems to be working
    pub fn get_auth_parameters(&self) -> HashMap<String, String> {
        let mut hm = HashMap::new();
        hm.insert(String::from("USERNAME"), self.username.clone());
        hm.insert(String::from("SRP_A"), big_to_hex(self.big_a.clone()));
        hm.insert(
            String::from("SECRET_HASH"),
            self.get_secret_hash(
                self.username.to_owned(),
                self.client_id.to_owned(),
                self.client_secret.to_owned(),
            )
            .clone(),
        );
        hm
    }

    // Tested working
    fn get_secret_hash(
        &self,
        username: String,
        client_id: String,
        client_secret: String,
    ) -> String {
        let message = format!("{}{}", username, client_id);

        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, client_secret.as_bytes());

        let tag = ring::hmac::sign(&key, message.as_bytes());

        encode(tag.as_ref())
    }

    pub fn get_challenge_response(
        &self,
        username: String,
        user_id_for_srp: String,
        salt_hex: String,
        srp_b_hex: String,
        secret_block_b64: String,
    ) -> HashMap<String, String> {
        let mut hm = HashMap::new();
        let timestamp = format!("{}", Utc::now().format("%a %b %-d %H:%M:%S %Z %Y"));

        let srp_b = hex_to_big(srp_b_hex);
        let salt = hex_to_big(salt_hex);

        // Checked above this line
        let hkdf = self.get_password_authentication_key(
            user_id_for_srp.clone(),
            self.password.to_owned(),
            srp_b,
            salt,
        );

        let secret_block_bytes =
            base64::decode(secret_block_b64.clone()).expect("Error decoding secret_block_b64");
        let pool_id: Vec<&str> = self.cognito_user_pool_id.split('_').collect();

        let msg = [
            pool_id[1].as_bytes(),
            user_id_for_srp.as_bytes(),
            &secret_block_bytes,
            timestamp.as_bytes(),
        ]
        .concat();

        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hkdf);
        let tag = ring::hmac::sign(&key, &msg);

        let sig_string = encode(tag.as_ref());

        hm.insert(String::from("TIMESTAMP"), timestamp);
        hm.insert(String::from("USERNAME"), username.clone());
        hm.insert(
            String::from("PASSWORD_CLAIM_SECRET_BLOCK"),
            secret_block_b64,
        );
        hm.insert(String::from("PASSWORD_CLAIM_SIGNATURE"), sig_string);
        hm.insert(
            String::from("SECRET_HASH"),
            self.get_secret_hash(
                username.clone(),
                self.client_id.to_owned(),
                self.client_secret.to_owned(),
            ),
        );
        hm
    }

    fn get_password_authentication_key(
        &self,
        username: String,
        password: String,
        srp_b: BigNum,
        salt: BigNum,
    ) -> [u8; 16] {
        let u_value = calculate_u(self.big_a.clone(), srp_b.clone());

        if u_value == BigNum::from(0u32) {
            panic!("u_value cannot be 0!");
        }

        let pool_id: Vec<&str> = self.cognito_user_pool_id.split('_').collect();
        let user_pass = format!("{}{}:{}", pool_id[1], username, password);

        let user_pass_digest = hash_sha256(user_pass.as_bytes());

        let x_value = hex_to_big(pad_hex_string(hex_hash(format!(
            "{}{}",
            pad_hex_big(salt),
            user_pass_digest
        ))));

        let g_mod_pow_xn = self.val_g.modpow(&x_value, &self.big_n);

        let int_value2 = &srp_b - &self.val_k * &g_mod_pow_xn;

        let s_value = int_value2.modpow(
            &hex_to_big(pad_hex_big(&self.small_a + &u_value * &x_value)),
            &self.big_n,
        );

        compute_hkdf(
            &hex::decode(pad_hex_big(s_value)).expect("Error decoding s_value into bytes"),
            &hex::decode(pad_hex_big(u_value)).expect("Error decoding u_value into bytes"),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    // #[test]
    // fn test_calculate_u() {
    //     let srp_a = BigNum::from(22u32);
    //     let srp_b = BigNum::from(23u32);

    //     let answer = BigNum::from_signed_bytes_be(&[
    //         150, 133, 178, 103, 136, 110, 84, 138, 191, 88, 182, 74, 131, 85, 108, 166, 88, 77, 60,
    //         34, 125, 69, 116, 151, 69, 34, 99, 220, 4, 93, 235, 143,
    //     ]);
    //     assert_eq!(calculate_u(srp_a, srp_b), answer);
    // }

    // #[test]
    // fn test_calculate_hkdr() {
    //     let ikm = BigNum::from(1u32);
    //     let salt = BigNum::parse_bytes("27".as_bytes(), 16).unwrap();

    //     assert_eq!(
    //         compute_hkdf(&ikm.to_signed_bytes_be(), &salt.to_signed_bytes_be()),
    //         [79, 112, 74, 173, 65, 16, 242, 64, 57, 51, 112, 195, 41, 117, 29, 216]
    //     );
    // }

    // #[test]
    // fn test_salt_hashing() {
    //     let salt_hex = String::from("31");

    //     let user_pass_digest = ring::digest::digest(
    //         &ring::digest::SHA256,
    //         String::from("6pjAdMAdna1b2de85-a0f9-489b-924c-32868ba0341b:Zoomtester123!").as_bytes(),
    //     );

    //     let bytestr = [
    //         &BigUint::parse_bytes(salt_hex.as_bytes(), 16)
    //             .unwrap()
    //             .to_bytes_be(),
    //         user_pass_digest.as_ref(),
    //     ]
    //     .concat();
    //     let sha_digest = ring::digest::digest(&ring::digest::SHA256, &bytestr);

    //     println!("{:?}", sha_digest);
    //     // panic!()
    // }

    // #[test]
    // fn test_secret_hash() {
    //     use crate::aws_srp::AwsSrpHelper;
    //     let srp_helper = AwsSrpHelper::new(
    //         "zoomtester9@gmail.com".into(),
    //         "Zoomtester1234!".into(),
    //         "us-west-2_6pjAdMAdn".into(),
    //         "4nnvoimmmgejnb5j8q5bctvj4i".into(),
    //         "mp85puvu1erob6ccr6a1k8od1legl1gu8cogl158ec97iatjtpj".into(),
    //     );

    //     println!("SECRET_HASH : {:?}", srp_helper.get_secret_hash("zoomtester9@gmail.com".into(), srp_helper.client_id.clone(), srp_helper.client_secret.clone()));
    //     println!("SECRET_HASH : {:?}", srp_helper.get_secret_hash("a1b2de85-a0f9-489b-924c-32868ba0341b".into(), srp_helper.client_id.clone(), srp_helper.client_secret.clone()));
    //     // panic!()
    // }

    // #[test]
    // fn test_bigint_modpow() {
    //     use num::bigint::BigUint;
    //     let x = BigUint::from(60u32);
    //     let y = BigUint::from(752u32);
    //     let z = BigUint::from(1053u32);

    //     println!("{:?}", x.modpow(&y, &z));
    //     // panic!()
    // }

    // #[test]
    // fn test_math_stuff() {
    //     let val_k = BigUint::from(356u32);
    //     let g_mod_pow_xn = BigUint::from(6u32);
    //     let b_val = BigUint::from(1789u32);

    //     let bigint = BigInt::from_signed_bytes_be(&(&val_k * &g_mod_pow_xn).to_bytes_be());
    //     let int_value_signed = BigInt::from_signed_bytes_be(&b_val.to_bytes_be()) - &bigint;
    //     let int_value2 = BigUint::from_bytes_be(&int_value_signed.to_signed_bytes_be());

    //     println!("{:?}", int_value_signed);
    //     // panic!()
    // }

    #[test]
    fn test_get_rand() {
        println!("{:?}", get_random(128));
        // panic!()
    }

    #[test]
    fn test_pad_hex_string() {
        assert_eq!(pad_hex_string("1".into()), String::from("01"))
    }
    #[test]
    fn test_pad_hex_string2() {
        assert_eq!(pad_hex_string("21".into()), String::from("21"))
    }
    #[test]
    fn test_pad_hex_string3() {
        assert_eq!(pad_hex_string("81".into()), String::from("0081"))
    }

    #[test]
    fn test_pad_hex_big() {
        assert_eq!(pad_hex_big(BigNum::from(1u32)), String::from("01"))
    }
    #[test]
    fn test_pad_hex_big2() {
        assert_eq!(pad_hex_big(BigNum::from(0x21u32)), String::from("21"))
    }
    #[test]
    fn test_pad_hex_big3() {
        assert_eq!(pad_hex_big(BigNum::from(0x81u32)), String::from("0081"))
    }
}
