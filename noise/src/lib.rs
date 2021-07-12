pub mod handshake;
pub mod cipher_state;
use snow::{params::NoiseParams, Builder};
use x25519_dalek;
use ed25519_dalek::Keypair as ED25519_Keypair;
use rand::rngs::OsRng;
pub fn foo() {
    let mut csprng = OsRng{};
    let kp = ED25519_Keypair::generate(&mut csprng);

    let params: NoiseParams = "Noise_XX_25519_AESGCM_SHA512".parse().unwrap();
    let noise = Builder::new(params)
    .local_private_key(&kp.secret.to_bytes()[..])
    .remote_public_key(&kp.public.to_bytes()[..])
    .build_initiator()
    .unwrap();
    println!("noise {:#?}", noise);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        foo();
    }
}
