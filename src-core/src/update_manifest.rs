//! What a release manifest signature covers, and how it is checked.
//!
//! `latest.json` is fetched over a pinned HTTPS endpoint, but TLS only says
//! the bytes came from the site — it says nothing if the site, its CDN or its
//! TLS terminator is the thing that was compromised (code review 2026-07-27,
//! P2). The manifest is therefore signed with an offline release key whose
//! public half is compiled into the client.
//!
//! **This file is the single source of truth for the signed bytes and is
//! included verbatim by `tools/release-signer` (via `#[path]`).** Keep it free
//! of crate-internal types: if signer and verifier ever disagree about one
//! byte, every client rejects every release.
//!
//! The signed form is an explicit line-oriented rendering rather than the raw
//! JSON: two JSON encoders that differ in key order or spacing would produce
//! different bytes for the same manifest, and the signature has to survive
//! the site re-serializing the file. Fields the signature does not cover must
//! never influence what the client does — today it acts only on the version
//! and the URLs, all of which are covered.

/// Domain separator. A future signed structure must use a different context
/// so a signature can never be replayed across formats.
pub const MANIFEST_SIG_CONTEXT: &str = "veyra-update-manifest-v1";

/// One platform entry as it is signed. Absent optional fields sign as empty.
#[derive(Debug, Clone, Default)]
pub struct SignedPlatform {
    pub key: String,
    pub file: String,
    pub size: String,
    pub sha256: String,
    pub store_url: String,
}

/// The manifest fields covered by the signature.
#[derive(Debug, Clone, Default)]
pub struct SignedManifest {
    pub schema: u64,
    pub version: String,
    pub published_at: String,
    pub download_url: String,
    pub platforms: Vec<SignedPlatform>,
}

/// Builds the exact bytes the release key signs.
///
/// Platform entries are sorted by key so the order they happen to appear in
/// the JSON cannot change the signature. A field containing a newline or tab
/// is refused rather than escaped: no legitimate field has one, and an
/// escaping scheme is one more thing signer and verifier could disagree on.
pub fn signing_bytes(manifest: &SignedManifest) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    out.push_str(MANIFEST_SIG_CONTEXT);
    out.push('\n');
    push_field(&mut out, "schema", &manifest.schema.to_string())?;
    push_field(&mut out, "version", &manifest.version)?;
    push_field(&mut out, "published_at", &manifest.published_at)?;
    push_field(&mut out, "download_url", &manifest.download_url)?;

    let mut platforms = manifest.platforms.clone();
    platforms.sort_by(|a, b| a.key.cmp(&b.key));
    for platform in &platforms {
        for value in [
            &platform.key,
            &platform.file,
            &platform.size,
            &platform.sha256,
            &platform.store_url,
        ] {
            reject_separators(value)?;
        }
        out.push_str(&format!(
            "platform={}\tfile={}\tsize={}\tsha256={}\tstore_url={}\n",
            platform.key, platform.file, platform.size, platform.sha256, platform.store_url
        ));
    }
    Ok(out.into_bytes())
}

fn push_field(out: &mut String, name: &str, value: &str) -> Result<(), String> {
    reject_separators(value)?;
    out.push_str(name);
    out.push('=');
    out.push_str(value);
    out.push('\n');
    Ok(())
}

fn reject_separators(value: &str) -> Result<(), String> {
    if value.contains('\n') || value.contains('\t') {
        return Err("manifest field contains a line or field separator".to_string());
    }
    Ok(())
}

/// Verifies a base64 Ed25519 signature over `signing_bytes` against a base64
/// public key. Every failure path — malformed key, malformed signature, wrong
/// signature — is one `false`; a caller has nothing useful to do with the
/// distinction and logging it would only describe the attacker's input.
pub fn verify_manifest_signature(
    public_key_b64: &str,
    signature_b64: &str,
    manifest: &SignedManifest,
) -> bool {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let Ok(bytes) = signing_bytes(manifest) else {
        return false;
    };
    let Ok(key_bytes) = STANDARD.decode(public_key_b64) else {
        return false;
    };
    let Ok(key_bytes) = <[u8; 32]>::try_from(key_bytes.as_slice()) else {
        return false;
    };
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature_bytes) = STANDARD.decode(signature_b64) else {
        return false;
    };
    let Ok(signature_bytes) = <[u8; 64]>::try_from(signature_bytes.as_slice()) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    ed25519_dalek::Verifier::verify(&verifying_key, &bytes, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};

    fn sample() -> SignedManifest {
        SignedManifest {
            schema: 1,
            version: "1.26.36".to_string(),
            published_at: "2026-07-28T09:00:00Z".to_string(),
            download_url: "https://veyra.social/download".to_string(),
            platforms: vec![
                SignedPlatform {
                    key: "windows-x64".to_string(),
                    file: "Veyra_1.26.36_x64-setup.exe".to_string(),
                    size: "51200000".to_string(),
                    sha256: "abc".to_string(),
                    store_url: String::new(),
                },
                SignedPlatform {
                    key: "android".to_string(),
                    file: "Veyra_1.26.36_arm64-v8a-release.apk".to_string(),
                    size: "72000000".to_string(),
                    sha256: "def".to_string(),
                    store_url: String::new(),
                },
            ],
        }
    }

    fn keypair() -> SigningKey {
        SigningKey::from_bytes(&[42_u8; 32])
    }

    #[test]
    fn a_signature_from_the_release_key_verifies() {
        let key = keypair();
        let manifest = sample();
        let signature = key.sign(&signing_bytes(&manifest).unwrap());
        let public_b64 = STANDARD.encode(key.verifying_key().to_bytes());
        let signature_b64 = STANDARD.encode(signature.to_bytes());
        assert!(verify_manifest_signature(
            &public_b64,
            &signature_b64,
            &manifest
        ));
    }

    #[test]
    fn platform_order_does_not_change_the_signed_bytes() {
        let mut reordered = sample();
        reordered.platforms.reverse();
        assert_eq!(
            signing_bytes(&sample()).unwrap(),
            signing_bytes(&reordered).unwrap()
        );
    }

    /// Changing anything the client acts on must invalidate the signature.
    #[test]
    fn every_covered_field_is_actually_covered() {
        let key = keypair();
        let original = sample();
        let public_b64 = STANDARD.encode(key.verifying_key().to_bytes());
        let signature_b64 =
            STANDARD.encode(key.sign(&signing_bytes(&original).unwrap()).to_bytes());

        let mutations: Vec<(&str, Box<dyn Fn(&mut SignedManifest)>)> = vec![
            ("schema", Box::new(|m: &mut SignedManifest| m.schema = 2)),
            (
                "version",
                Box::new(|m: &mut SignedManifest| m.version = "9.99.9".to_string()),
            ),
            (
                "published_at",
                Box::new(|m: &mut SignedManifest| {
                    m.published_at = "2030-01-01T00:00:00Z".to_string()
                }),
            ),
            (
                "download_url",
                Box::new(|m: &mut SignedManifest| {
                    m.download_url = "https://evil.com/veyra.exe".to_string()
                }),
            ),
            (
                "a platform file name",
                Box::new(|m: &mut SignedManifest| m.platforms[0].file = "evil.exe".to_string()),
            ),
            (
                "a platform digest",
                Box::new(|m: &mut SignedManifest| m.platforms[0].sha256 = "000".to_string()),
            ),
            (
                "a platform store url",
                Box::new(|m: &mut SignedManifest| {
                    m.platforms[1].store_url = "https://evil.com".to_string()
                }),
            ),
            (
                "an added platform",
                Box::new(|m: &mut SignedManifest| {
                    m.platforms.push(SignedPlatform {
                        key: "linux".to_string(),
                        ..SignedPlatform::default()
                    })
                }),
            ),
            (
                "a removed platform",
                Box::new(|m: &mut SignedManifest| {
                    m.platforms.pop();
                }),
            ),
        ];
        for (label, mutate) in mutations {
            let mut tampered = original.clone();
            mutate(&mut tampered);
            assert!(
                !verify_manifest_signature(&public_b64, &signature_b64, &tampered),
                "the signature survived a change to {label}"
            );
        }
    }

    #[test]
    fn another_key_cannot_sign_for_us() {
        let manifest = sample();
        let attacker = SigningKey::from_bytes(&[7_u8; 32]);
        let signature_b64 =
            STANDARD.encode(attacker.sign(&signing_bytes(&manifest).unwrap()).to_bytes());
        let ours = STANDARD.encode(keypair().verifying_key().to_bytes());
        assert!(!verify_manifest_signature(&ours, &signature_b64, &manifest));
    }

    #[test]
    fn malformed_keys_and_signatures_are_refused_not_panicked_on() {
        let manifest = sample();
        for (key, signature) in [
            ("", ""),
            ("not base64!!", "not base64!!"),
            (
                STANDARD.encode([1_u8; 31]).as_str(),
                STANDARD.encode([1_u8; 64]).as_str(),
            ),
            (
                STANDARD.encode([1_u8; 32]).as_str(),
                STANDARD.encode([1_u8; 8]).as_str(),
            ),
        ] {
            assert!(!verify_manifest_signature(key, signature, &manifest));
        }
    }

    #[test]
    fn a_field_with_a_separator_cannot_be_signed() {
        let mut sneaky = sample();
        sneaky.version = "1.0.0\nversion=2.0.0".to_string();
        assert!(signing_bytes(&sneaky).is_err());
    }
}
