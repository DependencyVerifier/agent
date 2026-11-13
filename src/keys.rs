//! Ed25519 keys in their protocol forms (§2): `ed25519:<base64>` and the `SHA256:<base64 without padding>` fingerprint.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub struct AgentKey {
    signing: SigningKey,
}

impl AgentKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("the system random generator");
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public_text(&self) -> String {
        public_text(self.signing.verifying_key().as_bytes())
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(self.signing.verifying_key().as_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

pub fn public_text(raw: &[u8; 32]) -> String {
    format!("ed25519:{}", STANDARD.encode(raw))
}

pub fn fingerprint(raw: &[u8; 32]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(raw)))
}

/// The pinned console key, read from `AGENT_CONSOLE_PUBKEY`.
#[derive(Clone)]
pub struct ConsoleKey {
    key: VerifyingKey,
}

impl ConsoleKey {
    pub fn parse(text: &str) -> Result<Self, String> {
        let encoded = text
            .trim()
            .strip_prefix("ed25519:")
            .ok_or("the console key must start with ed25519:")?;
        let raw: [u8; 32] = STANDARD
            .decode(encoded)
            .map_err(|_| "the console key is not base64")?
            .try_into()
            .map_err(|_| "the console key is not 32 bytes")?;
        let key =
            VerifyingKey::from_bytes(&raw).map_err(|_| "the console key is not an Ed25519 key")?;
        Ok(Self { key })
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(self.key.as_bytes())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(bytes) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        self.key
            .verify_strict(message, &Signature::from_bytes(&bytes))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(hex: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    #[test]
    fn reproduces_the_key_forms_of_the_vectors() {
        let agent = AgentKey::from_seed(seed(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        assert_eq!(
            agent.public_text(),
            "ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
        );
        assert_eq!(
            agent.fingerprint(),
            "SHA256:If4x36FUomFia/hUBG/SJxt77UtqvkWqWId+9H+XIbk"
        );

        let console =
            ConsoleKey::parse("ed25519:PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=").unwrap();
        assert_eq!(
            console.fingerprint(),
            "SHA256:OfcT0KZEJT8EUpQhufUbmwiXnQgpWVnE85kO5hf1E58"
        );
        assert!(ConsoleKey::parse("PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=").is_err());
        assert!(ConsoleKey::parse("ed25519:AAAA").is_err());
    }
}
