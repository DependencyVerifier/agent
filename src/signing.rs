//! Request signatures, profile `depverify-agent-v1` (protocol §4): RFC 9421 with Ed25519, over the method, the
//! target URI, the `Content-Digest` of the bytes sent (when there is a body) and the `Date`.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::keys::AgentKey;
use crate::time;

pub struct SignedHeaders {
    pub date: String,
    pub content_digest: Option<String>,
    pub signature_input: String,
    pub signature: String,
}

/// `sha-256=:<base64>:` (RFC 9530) of the bytes as sent.
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

pub fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the system random generator");
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn sign(
    key: &AgentKey,
    method: &str,
    target_uri: &str,
    body: Option<&[u8]>,
    created: i64,
    nonce: &str,
) -> SignedHeaders {
    let date = time::imf_fixdate(created);
    let content_digest = body.map(content_digest);
    let components = if content_digest.is_some() {
        r#"("@method" "@target-uri" "content-digest" "date")"#
    } else {
        r#"("@method" "@target-uri" "date")"#
    };
    let params = format!(
        r#"{components};created={created};expires={};keyid="{}";alg="ed25519";nonce="{nonce}";tag="depverify-agent-v1""#,
        created + 300,
        key.fingerprint()
    );
    let mut base = format!("\"@method\": {method}\n\"@target-uri\": {target_uri}\n");
    if let Some(digest) = &content_digest {
        base.push_str(&format!("\"content-digest\": {digest}\n"));
    }
    base.push_str(&format!(
        "\"date\": {date}\n\"@signature-params\": {params}"
    ));
    let signature = key.sign(base.as_bytes());

    SignedHeaders {
        date,
        content_digest,
        signature_input: format!("sig1={params}"),
        signature: format!("sig1=:{}:", STANDARD.encode(signature)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reproduces_the_request_vector_byte_for_byte() {
        let seed: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(
                    &"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"[i..i + 2],
                    16,
                )
                .unwrap()
            })
            .collect();
        let key = AgentKey::from_seed(seed.try_into().unwrap());
        let body = br#"{"protocol_version":1,"agent_version":"0.1.0","order_results":[]}"#;
        let headers = sign(
            &key,
            "POST",
            "https://console.example.com/agent/v1/poll",
            Some(body),
            1_794_211_200,
            "aw89HJouS3-MXR4vOktcbQ",
        );

        assert_eq!(headers.date, "Mon, 09 Nov 2026 08:00:00 GMT");
        assert_eq!(
            headers.content_digest.as_deref(),
            Some("sha-256=:wrOHkjP1C0PqxRidBPiMp7ghXYZ6r08JLoETslNB/ac=:")
        );
        assert_eq!(
            headers.signature_input,
            r#"sig1=("@method" "@target-uri" "content-digest" "date");created=1794211200;expires=1794211500;keyid="SHA256:If4x36FUomFia/hUBG/SJxt77UtqvkWqWId+9H+XIbk";alg="ed25519";nonce="aw89HJouS3-MXR4vOktcbQ";tag="depverify-agent-v1""#
        );
        assert_eq!(
            headers.signature,
            "sig1=:z/RBw4TRiJJ6cs8RHU48XCZZGODztPa8/ATusvqtnMJd5zR4oocmnQP4oxfljI0JXdsP+QyM69d0Go0uNjnpDw==:"
        );
    }

    #[test]
    fn signs_without_a_digest_when_there_is_no_body() {
        let key = AgentKey::from_seed([7; 32]);
        let headers = sign(&key, "GET", "https://c.example/agent/v1/x", None, 0, "n");
        assert!(headers.content_digest.is_none());
        assert!(
            headers
                .signature_input
                .starts_with(r#"sig1=("@method" "@target-uri" "date");created=0;expires=300;"#)
        );
        assert_eq!(random_nonce().len(), 22);
    }
}
