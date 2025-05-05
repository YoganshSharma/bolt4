use color_eyre::{
    eyre::{eyre, OptionExt},
    Result,
};
use crypto::{
    chacha20::ChaCha20, hmac::Hmac, mac::Mac, sha2::Sha256,
    symmetriccipher::SynchronousStreamCipher,
};
use secp256k1::{
    ecdh::SharedSecret,
    hashes::{sha256, Hash},
    PublicKey, Scalar, Secp256k1, SecretKey,
};
use serde_json::Value;
type HmacSha256 = Hmac<Sha256>;
const ONION_DATA_LEN: usize = 1300;

#[derive(Clone)]
pub struct Hop {
    pub pubkey: PublicKey,
    pub payload: Vec<u8>,
}

#[allow(dead_code)]
enum OnionKeyType<'a> {
    Rho,
    Mu,
    Um,
    Pad,
    Other(&'a [u8]),
}

fn key_generator(keytype: OnionKeyType, secret: impl AsRef<[u8]>) -> [u8; 32] {
    let key = match keytype {
        OnionKeyType::Rho => b"rho".as_slice(),
        OnionKeyType::Mu => b"mu",
        OnionKeyType::Um => b"um",
        OnionKeyType::Pad => b"pad",
        OnionKeyType::Other(k) => k,
    };
    let mut hma = HmacSha256::new(Sha256::new(), key);
    hma.input(secret.as_ref());
    let mut output = [0u8; 32];
    hma.raw_result(&mut output);
    output
}

#[derive(Clone)]
#[allow(dead_code)]
struct OnionKeys {
    shared_secret: SharedSecret,
    ephemeral_pubkey: PublicKey,
    ephemeral_privkey: SecretKey,
    rho: [u8; 32],
    mu: [u8; 32],
}
fn compute_blinding_factor(
    ephemeral_pubkey: PublicKey,
    shared_secret: SharedSecret,
) -> Result<Scalar> {
    let mut input = ephemeral_pubkey.serialize().to_vec();
    input.extend_from_slice(&shared_secret.secret_bytes());
    let blinding_factor = sha256::Hash::hash(&input);
    let blinding_factor = Scalar::from_be_bytes(blinding_factor.to_byte_array())?;
    Ok(blinding_factor)
}
pub struct Input {
    session_key: SecretKey,
    associated_data: Option<Vec<u8>>,
    hops: Vec<Hop>,
    keys: Option<Vec<OnionKeys>>,
}
impl Input {
    fn compute_keys(&mut self) -> Result<()> {
        let mut res = Vec::new();
        let secp = Secp256k1::new();
        let mut ephemeral_privkey = self.session_key;
        let mut ephemeral_pubkey = PublicKey::from_secret_key(&secp, &ephemeral_privkey);
        let shared_secret = SharedSecret::new(&self.hops[0].pubkey, &self.session_key);
        let rho = key_generator(OnionKeyType::Rho, shared_secret);
        let mu = key_generator(OnionKeyType::Mu, shared_secret);
        res.push(OnionKeys {
            shared_secret,
            rho,
            ephemeral_pubkey,
            ephemeral_privkey,
            mu,
        });

        let mut blinding_factor = compute_blinding_factor(ephemeral_pubkey, shared_secret)?;
        for hop in self.hops.iter().skip(1) {
            ephemeral_privkey = ephemeral_privkey.mul_tweak(&blinding_factor)?;
            ephemeral_pubkey = PublicKey::from_secret_key(&secp, &ephemeral_privkey);
            let shared_secret = SharedSecret::new(&hop.pubkey, &ephemeral_privkey);
            let rho = key_generator(OnionKeyType::Rho, shared_secret);
            let mu = key_generator(OnionKeyType::Mu, shared_secret);
            res.push(OnionKeys {
                shared_secret,
                rho,
                ephemeral_pubkey,
                ephemeral_privkey,
                mu,
            });
            blinding_factor = compute_blinding_factor(ephemeral_pubkey, shared_secret)?;
        }
        self.keys = Some(res);
        Ok(())
    }

    fn get_init_packet(&self) -> [u8; ONION_DATA_LEN] {
        let mut packet_data = [0; ONION_DATA_LEN];
        let padding_key = key_generator(OnionKeyType::Pad, self.session_key.secret_bytes());
        let mut chacha = ChaCha20::new(&padding_key, &[0; 12]);
        chacha.process(&[0; ONION_DATA_LEN], &mut packet_data);
        packet_data
    }

    fn get_filler(&self) -> Result<Vec<u8>> {
        const HOP_SIZE: usize = 65;
        let mut res = Vec::with_capacity(HOP_SIZE * (self.hops.len() - 1));

        let mut pos = 0;
        for (i, (hop, keys)) in self
            .hops
            .iter()
            .zip(self.keys.as_ref().unwrap().iter())
            .enumerate()
        {
            if i == self.hops.len() - 1 {
                break;
            }
            let payload = &hop.payload;

            let mut chacha = ChaCha20::new(&keys.rho, &[0u8; 12]);
            // Skip bytes
            for _ in 0..(ONION_DATA_LEN - pos) {
                let mut dummy = [0; 1];
                chacha.process(&dummy.clone(), &mut dummy);
            }
            pos += payload.len() + 32;
            res.resize(pos, 0u8);
            chacha.process(&res.clone(), &mut res);
            if pos > ONION_DATA_LEN {
                return Err(eyre!(""));
            }
        }
        Ok(res)
    }
    fn get_onion_bytes(&mut self) -> Result<Vec<u8>> {
        self.compute_keys()?;
        let mut packet_data = self.get_init_packet();
        let filler = self.get_filler()?;

        let mut hmac_res = [0u8; 32];
        for (i, (hop, keys)) in self
            .hops
            .iter()
            .zip(self.keys.clone().unwrap().iter())
            .rev()
            .enumerate()
        {
            // right shift
            let amt = hop.payload.len() + 32;
            for i in (amt..packet_data.len()).rev() {
                packet_data[i] = packet_data[i - amt];
            }
            for i in packet_data.iter_mut().take(amt) {
                *i = 0;
            }
            packet_data[0..hop.payload.len()].copy_from_slice(&hop.payload);
            packet_data[hop.payload.len()..(hop.payload.len() + 32)].copy_from_slice(&hmac_res);

            let mut chacha = ChaCha20::new(&keys.rho, &[0u8; 12]);
            chacha.process(&packet_data.clone(), &mut packet_data);

            if i == 0 {
                let stop_index = packet_data.len();
                let start_index = stop_index.checked_sub(filler.len()).ok_or_eyre("")?;
                packet_data[start_index..stop_index].copy_from_slice(&filler[..]);
            }
            let mut hmac = HmacSha256::new(Sha256::new(), &keys.mu);
            hmac.input(&packet_data);
            if let Some(associated_data) = &self.associated_data {
                hmac.input(&associated_data[..]);
            }

            hmac.raw_result(&mut hmac_res);
        }
        let mut res = Vec::new();
        res.push(0x00u8);
        let secp = Secp256k1::new();
        res.extend_from_slice(&PublicKey::from_secret_key(&secp, &self.session_key).serialize());
        res.extend_from_slice(&packet_data);
        res.extend_from_slice(&hmac_res);
        Ok(res)
    }

    pub fn get_onion_hex(&mut self) -> Result<String> {
        Ok(hex::encode(self.get_onion_bytes()?))
    }
}

pub fn parse_input(input: impl AsRef<[u8]>) -> Result<Input> {
    let val: Value = serde_json::from_slice(input.as_ref())?;
    let session_key = SecretKey::from_slice(&hex::decode(
        val.get("session_key")
            .ok_or_eyre("session_key not found in the input")?
            .as_str()
            .ok_or_eyre("session_key not a string")?,
    )?)?;
    let associated_data = val
        .get("associated_data")
        .map(|v| hex::decode(v.as_str().unwrap()).unwrap());
    let hops_raw = val
        .get("hops")
        .ok_or_eyre("hops not found in the input")?
        .as_array()
        .ok_or_eyre("hops not an array")?;
    let mut hops = Vec::new();
    for hop in hops_raw {
        hops.push(Hop {
            pubkey: PublicKey::from_slice(&hex::decode(
                hop.get("pubkey")
                    .ok_or_eyre("pubkey not found in the input")?
                    .as_str()
                    .ok_or_eyre("pubkey not a string")?,
            )?)?,
            payload: hex::decode(
                hop.get("payload")
                    .ok_or_eyre("payload not found in the input")?
                    .as_str()
                    .ok_or_eyre("payload not a string")?,
            )?,
        });
    }
    let inp = Input {
        session_key,
        associated_data,
        hops,
        keys: None,
    };
    Ok(inp)
}
