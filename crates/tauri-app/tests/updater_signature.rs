use base64::{engine::general_purpose::STANDARD, Engine as _};
use minisign_verify::{PublicKey, Signature};

#[test]
fn checked_in_updater_identity_verifies_a_real_tauri_signature() {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).expect("valid Tauri config");
    let encoded_public_key = config["plugins"]["updater"]["pubkey"]
        .as_str()
        .expect("updater public key");
    let public_key_text = String::from_utf8(
        STANDARD
            .decode(encoded_public_key)
            .expect("base64 updater public key"),
    )
    .expect("UTF-8 updater public key");
    let public_key = PublicKey::decode(&public_key_text).expect("minisign updater public key");

    let encoded_signature = include_str!("fixtures/signed-update-fixture.txt.sig").trim();
    let signature_text = String::from_utf8(
        STANDARD
            .decode(encoded_signature)
            .expect("base64 updater signature"),
    )
    .expect("UTF-8 updater signature");
    let signature = Signature::decode(&signature_text).expect("minisign updater signature");
    let fixture = include_bytes!("fixtures/signed-update-fixture.txt");

    public_key
        .verify(fixture, &signature, true)
        .expect("fixture must verify with the configured updater identity");

    let mut tampered = fixture.to_vec();
    tampered[0] ^= 1;
    assert!(
        public_key.verify(&tampered, &signature, true).is_err(),
        "tampered updater bytes must fail signature verification"
    );
}
