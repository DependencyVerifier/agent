//! CycloneDX 1.6, profile §8.5: no serialNumber, no timestamp, components sorted by purl, keys sorted (serde_json
//! maps are ordered): unchanged content, unchanged digest.

use serde_json::{Value, json};

use super::{CYCLONEDX_MEDIA_TYPE, Document, Package};

pub fn document(
    subject_key: &str,
    component_type: &str,
    name: &str,
    packages: &[Package],
) -> Document {
    let mut packages: Vec<&Package> = packages.iter().collect();
    packages.sort();
    packages.dedup_by(|a, b| a.purl == b.purl);
    let components: Vec<Value> = packages
        .iter()
        .map(|p| {
            json!({
                "type": "library",
                "bom-ref": p.purl,
                "name": p.name,
                "version": p.version,
                "purl": p.purl,
                "properties": [
                    {"name": "depverify:dependency", "value": if p.direct { "direct" } else { "transitive" }},
                    {"name": "depverify:package-manager", "value": p.manager},
                    {"name": "depverify:source", "value": p.source},
                ],
            })
        })
        .collect();
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": {"type": component_type, "name": name, "bom-ref": subject_key}},
        "components": components,
    });
    Document::new(
        serde_json::to_vec(&bom).expect("serializable"),
        CYCLONEDX_MEDIA_TYPE,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(purl: &str) -> Package {
        Package {
            purl: purl.into(),
            name: "n".into(),
            version: "1".into(),
            manager: "npm",
            source: "package-lock.json".into(),
            direct: false,
        }
    }

    #[test]
    fn is_deterministic_and_follows_the_profile() {
        let a = document(
            "path:/srv/app",
            "application",
            "app",
            &[
                package("pkg:npm/b@1"),
                package("pkg:npm/a@1"),
                package("pkg:npm/a@1"),
            ],
        );
        let b = document(
            "path:/srv/app",
            "application",
            "app",
            &[package("pkg:npm/a@1"), package("pkg:npm/b@1")],
        );
        assert_eq!(a.digest, b.digest);
        let bom: Value = serde_json::from_slice(&a.bytes).unwrap();
        assert!(bom.get("serialNumber").is_none());
        assert_eq!(bom["specVersion"], "1.6");
        assert_eq!(bom["components"].as_array().unwrap().len(), 2);
        assert_eq!(bom["components"][0]["purl"], "pkg:npm/a@1");
        assert_eq!(bom["metadata"]["component"]["bom-ref"], "path:/srv/app");
        assert_eq!(a.media_type, CYCLONEDX_MEDIA_TYPE);
        assert!(a.digest.starts_with("sha256:") && a.digest.len() == 71);
    }
}
