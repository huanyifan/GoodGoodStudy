use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
pub type Result<T> = std::result::Result<T, &'static str>;
pub const ENDPOINT: &str = "https://yifan.im/tools/goodgoodstudy/config.json";
pub const PROTOCOL: &str = "GoodGoodStudy.Config.ECDH-P256.HKDF-SHA256.v2";
pub const ALGORITHM: &str = "AES-256-CBC+HMAC-SHA256";

pub type TraceSink<'a> = Option<&'a mut dyn FnMut(serde_json::Value)>;
fn emit(sink: &mut TraceSink<'_>, step: &str, details: serde_json::Value) {
    if let Some(write) = sink {
        write(serde_json::json!({"side":"client", "step":step, "details":details}));
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub device_id: String,
    pub access_token: String,
}
impl Profile {
    pub fn create() -> Self {
        let mut token = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *token);
        Self {
            device_id: uuid::Uuid::new_v4().to_string(),
            access_token: B64.encode(token.as_slice()),
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.device_id.len() != 36 || uuid::Uuid::parse_str(&self.device_id).is_err() {
            return Err("invalid device ID");
        }
        let token = Zeroizing::new(
            B64.decode(&self.access_token)
                .map_err(|_| "invalid credential")?,
        );
        if token.len() != 32 || B64.encode(&*token) != self.access_token {
            return Err("invalid credential");
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct MailConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub enable_ssl: bool,
    pub sender: String,
    pub recipient: String,
    pub username: String,
    pub password: String,
}
impl Default for MailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: String::new(),
            port: 587,
            enable_ssl: true,
            sender: String::new(),
            recipient: String::new(),
            username: String::new(),
            password: String::new(),
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Config {
    pub interval_seconds: u32,
    pub batch_size: usize,
    pub screenshot_directory: String,
    pub retention_days: u32,
    #[serde(rename = "maxStorageMB")]
    pub max_storage_mb: u32,
    pub mail: MailConfig,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            interval_seconds: 180,
            batch_size: 10,
            screenshot_directory: String::new(),
            retention_days: 7,
            max_storage_mb: 512,
            mail: MailConfig::default(),
        }
    }
}
impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 65536 {
            return Err("configuration too large");
        }
        let c: Self = serde_json::from_slice(bytes).map_err(|_| "invalid configuration")?;
        if !(1..=86400).contains(&c.interval_seconds)
            || !(1..=100).contains(&c.batch_size)
            || !(1..=365).contains(&c.retention_days)
            || !(16..=8192).contains(&c.max_storage_mb)
        {
            return Err("configuration range invalid");
        }
        if !c.screenshot_directory.is_empty() && !Path::new(&c.screenshot_directory).is_absolute() {
            return Err("directory must be absolute");
        }
        if c.mail.enabled {
            if c.mail.host.is_empty()
                || c.mail.port == 0
                || c.mail.port == 465
                || !c.mail.enable_ssl
                || c.mail.username.is_empty()
                || c.mail.password.is_empty()
            {
                return Err("invalid SMTP settings");
            }
            let _: lettre::message::Mailbox =
                c.mail.sender.parse().map_err(|_| "invalid sender")?;
            let _: lettre::message::Mailbox =
                c.mail.recipient.parse().map_err(|_| "invalid recipient")?;
        }
        Ok(c)
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Handshake {
    version: u8,
    device_id: String,
    client_public_key: String,
    client_nonce: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    version: u8,
    algorithm: String,
    iv: String,
    ciphertext: String,
    mac: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    version: u8,
    key_agreement: String,
    server_public_key: String,
    server_nonce: String,
    payload: Envelope,
}
pub struct Session {
    secret: EphemeralSecret,
    pub request: Handshake,
    point: Vec<u8>,
    nonce: [u8; 32],
}
impl Session {
    pub fn new(device: &str) -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let point = PublicKey::from(&secret)
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let request = Handshake {
            version: 2,
            device_id: device.to_owned(),
            client_public_key: B64.encode(&point),
            client_nonce: B64.encode(nonce),
        };
        Self {
            secret,
            request,
            point,
            nonce,
        }
    }
    pub fn decrypt(&self, r: &Response) -> Result<Config> {
        self.decrypt_with_trace(r, None)
    }
    pub fn trace_handshake(&self, mut trace: TraceSink<'_>) {
        emit(
            &mut trace,
            "01.generate_ephemeral_handshake",
            serde_json::json!({
                "curve":"P-256 / secp256r1", "publicKeyEncoding":"SEC1 uncompressed, 65 bytes (04 || X || Y), Base64",
                "clientPublicKey":self.request.client_public_key, "clientNonce":self.request.client_nonce,
                "nonceBytes":32, "deviceId":"[redacted]", "privateKey":"[memory only; redacted]"
            }),
        );
    }
    pub fn decrypt_with_trace(&self, r: &Response, mut trace: TraceSink<'_>) -> Result<Config> {
        if r.version != 2
            || r.key_agreement != PROTOCOL
            || r.payload.version != 1
            || r.payload.algorithm != ALGORITHM
        {
            return Err("invalid session response");
        }
        let public = B64
            .decode(&r.server_public_key)
            .map_err(|_| "invalid point")?;
        if public.len() != 65 || public[0] != 4 {
            return Err("invalid point");
        }
        let peer = PublicKey::from_sec1_bytes(&public).map_err(|_| "invalid point")?;
        let nonce = B64.decode(&r.server_nonce).map_err(|_| "invalid nonce")?;
        if nonce.len() != 32 {
            return Err("invalid nonce");
        }
        emit(
            &mut trace,
            "04.validate_server_handshake",
            serde_json::json!({
                "version":r.version, "protocol":r.key_agreement, "algorithm":r.payload.algorithm,
                "serverPublicKey":r.server_public_key, "serverNonce":r.server_nonce,
                "pointOnCurve":true, "serverNonceBytes":nonce.len()
            }),
        );
        let shared = self.secret.diffie_hellman(&peer);
        let hashed = Zeroizing::new(Sha256::digest(shared.raw_secret_bytes()).to_vec());
        emit(
            &mut trace,
            "05.ecdh_and_sha256",
            serde_json::json!({
                "calculation":"Z = ECDH(client_private, server_public); IKM = SHA256(Z)",
                "serverEquivalent":"Z = ECDH(server_private, client_public)",
                "rawSecretBytes":32, "ikmBytes":32, "privateKey":"[redacted]", "Z":"[redacted]", "IKM":"[redacted]"
            }),
        );
        let mut salt = self.nonce.to_vec();
        salt.extend_from_slice(&nonce);
        let mut info = format!("{}|{}|", PROTOCOL, self.request.device_id).into_bytes();
        info.extend_from_slice(&self.point);
        info.extend_from_slice(&public);
        info.extend_from_slice(&self.nonce);
        info.extend_from_slice(&nonce);
        let mut key = Zeroizing::new([0u8; 64]);
        Hkdf::<Sha256>::new(Some(&salt), &hashed)
            .expand(&info, &mut *key)
            .map_err(|_| "HKDF failed")?;
        emit(
            &mut trace,
            "06.hkdf_sha256",
            serde_json::json!({
                "saltLayout":"client_nonce[32] || server_nonce[32]", "saltBase64":B64.encode(&salt),
                "infoLayout":"UTF8(protocol + '|' + device_id + '|') || client_public[65] || server_public[65] || client_nonce[32] || server_nonce[32]",
                "infoBytes":info.len(), "infoSha256":format!("{:x}",Sha256::digest(&info)),
                "outputBytes":64, "split":"OKM[0..32] = AES-256 key; OKM[32..64] = HMAC-SHA256 key",
                "keys":"[memory only; redacted]"
            }),
        );
        let iv = B64.decode(&r.payload.iv).map_err(|_| "invalid IV")?;
        if iv.len() != 16 {
            return Err("invalid IV");
        }
        let ciphertext = B64
            .decode(&r.payload.ciphertext)
            .map_err(|_| "invalid ciphertext")?;
        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 || ciphertext.len() > 65552 {
            return Err("invalid ciphertext");
        }
        let tag = B64.decode(&r.payload.mac).map_err(|_| "invalid MAC")?;
        if tag.len() != 32 {
            return Err("invalid MAC");
        }
        emit(
            &mut trace,
            "07.encrypted_envelope",
            serde_json::json!({
                "ivBase64":r.payload.iv, "ivBytes":iv.len(), "ciphertextBytes":ciphertext.len(),
                "ciphertextSha256":format!("{:x}",Sha256::digest(&ciphertext)), "macBase64":r.payload.mac,
                "macInputLayout":format!("ASCII('GoodGoodStudy.Config.v1|{}|') || IV[16] || ciphertext",ALGORITHM),
                "macBytes":tag.len(), "verification":"constant-time HMAC verify before AES decryption"
            }),
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&key[32..]).map_err(|_| "MAC failed")?;
        mac.update(format!("GoodGoodStudy.Config.v1|{}|", ALGORITHM).as_bytes());
        mac.update(&iv);
        mac.update(&ciphertext);
        mac.verify_slice(&tag)
            .map_err(|_| "authentication failed")?;
        emit(
            &mut trace,
            "08.hmac_verified",
            serde_json::json!({"valid":true, "decryptAllowed":true}),
        );
        let decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(&key[..32], &iv)
            .map_err(|_| "cipher failed")?;
        let plain = Zeroizing::new(
            decryptor
                .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
                .map_err(|_| "cipher failed")?,
        );
        let config = Config::parse(&plain)?;
        emit(
            &mut trace,
            "09.aes_decrypt_and_validate",
            serde_json::json!({
                "cipher":"AES-256-CBC", "padding":"PKCS#7, 16-byte blocks", "paddingValid":true,
                "plaintextBytes":plain.len(), "jsonValid":true, "configurationRangesValid":true,
                "intervalSeconds":config.interval_seconds, "batchSize":config.batch_size,
            "usesDefaultScreenshotDirectory":config.screenshot_directory.is_empty(),
                "mailEnabled":config.mail.enabled, "smtpPort":config.mail.port, "smtpTls":config.mail.enable_ssl,
                "mailAddressesAndPassword":"[redacted]", "plaintextConfiguration":"[redacted]"
            }),
        );
        emit(
            &mut trace,
            "10.session_lifetime",
            serde_json::json!({
                "keyPersistence":false, "plaintextCache":false,
                "cleanup":"Rust Zeroizing buffers / cryptographic type drop; no private keys or session key bytes emitted"
            }),
        );
        Ok(config)
    }
}
pub fn fetch(address: &str, profile: &Profile) -> Result<Config> {
    fetch_with_trace(address, profile, None)
}
pub fn fetch_with_trace(
    address: &str,
    profile: &Profile,
    mut trace: TraceSink<'_>,
) -> Result<Config> {
    profile.validate()?;
    let url = reqwest::Url::parse(address).map_err(|_| "invalid URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("HTTPS required");
    }
    let session = Session::new(&profile.device_id);
    session.trace_handshake(
        trace
            .as_mut()
            .map(|sink| &mut **sink as &mut dyn FnMut(serde_json::Value)),
    );
    emit(
        &mut trace,
        "02.https_request",
        serde_json::json!({
            "method":"POST", "host":url.host_str(), "path":url.path(), "tlsCertificateVerification":true,
            "redirectsAllowed":false, "timeoutSeconds":15, "authorization":"Bearer [redacted]",
            "requestBody":"version, deviceId, clientPublicKey, clientNonce; no private key or session encryption key"
        }),
    );
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "HTTPS unavailable")?;
    let response = client
        .post(url)
        .bearer_auth(&profile.access_token)
        .json(&session.request)
        .send()
        .map_err(|error| {
            use std::error::Error;
            let mut codes = Vec::new();
            let mut cause = error.source();
            while let Some(value) = cause {
                if let Some(io) = value.downcast_ref::<std::io::Error>() {
                    if let Some(code) = io.raw_os_error() {
                        codes.push(code);
                    }
                }
                cause = value.source();
            }
            eprintln!(
                "HTTPS transport failed: connect={}, timeout={}, os_codes={:?}",
                error.is_connect(),
                error.is_timeout(),
                codes
            );
            "HTTPS configuration unavailable"
        })?;
    emit(
        &mut trace,
        "03.https_response",
        serde_json::json!({"status":response.status().as_u16()}),
    );
    if response.status() != reqwest::StatusCode::OK {
        return Err("configuration access failed");
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    response
        .take(131073)
        .read_to_end(&mut bytes)
        .map_err(|_| "response read failed")?;
    if bytes.len() > 131072 {
        return Err("response too large");
    }
    let r: Response = serde_json::from_slice(&bytes).map_err(|_| "invalid session response")?;
    session.decrypt_with_trace(&r, trace)
}
pub fn parse_ini(data: &str) -> Result<Config> {
    let mut values = std::collections::HashMap::new();
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['[', ';', '#']) {
            continue;
        }
        let (k, v) = line.split_once('=').ok_or("invalid INI")?;
        values.insert(k.trim(), v.trim().trim_matches(['\'', '"']));
    }
    let value = |key: &str| values.get(key).copied().ok_or("missing INI field");
    let interval: u32 = value("timeInterval")?
        .parse()
        .map_err(|_| "invalid interval")?;
    let c = Config {
        interval_seconds: interval.checked_mul(60).ok_or("invalid interval")?,
        mail: MailConfig {
            enabled: true,
            host: value("smtpServer")?.to_owned(),
            sender: value("senderMail")?.to_owned(),
            recipient: value("toMail")?.to_owned(),
            username: value("senderMail")?.to_owned(),
            password: value("tokenCode")?.to_owned(),
            ..Default::default()
        },
        ..Default::default()
    };
    let data = Zeroizing::new(serde_json::to_vec(&c).map_err(|_| "invalid configuration")?);
    Config::parse(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    fn reply(client: &Session) -> Response {
        reply_with_plain(client, br#"{"intervalSeconds":42}"#)
    }
    fn reply_with_plain(client: &Session, plain: &[u8]) -> Response {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = PublicKey::from(&secret)
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let peer = PublicKey::from_sec1_bytes(&client.point).unwrap();
        let shared = secret.diffie_hellman(&peer);
        let hashed = Zeroizing::new(Sha256::digest(shared.raw_secret_bytes()).to_vec());
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let mut salt = client.nonce.to_vec();
        salt.extend_from_slice(&nonce);
        let mut info = format!("{}|{}|", PROTOCOL, client.request.device_id).into_bytes();
        info.extend_from_slice(&client.point);
        info.extend_from_slice(&public);
        info.extend_from_slice(&client.nonce);
        info.extend_from_slice(&nonce);
        let mut key = Zeroizing::new([0u8; 64]);
        Hkdf::<Sha256>::new(Some(&salt), &hashed)
            .expand(&info, &mut *key)
            .unwrap();
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        let encrypted = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key[..32], &iv)
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(plain);
        let mut mac = Hmac::<Sha256>::new_from_slice(&key[32..]).unwrap();
        mac.update(format!("GoodGoodStudy.Config.v1|{}|", ALGORITHM).as_bytes());
        mac.update(&iv);
        mac.update(&encrypted);
        Response {
            version: 2,
            key_agreement: PROTOCOL.into(),
            server_public_key: B64.encode(public),
            server_nonce: B64.encode(nonce),
            payload: Envelope {
                version: 1,
                algorithm: ALGORITHM.into(),
                iv: B64.encode(iv),
                ciphertext: B64.encode(encrypted),
                mac: B64.encode(mac.finalize().into_bytes()),
            },
        }
    }
    #[test]
    fn session_round_trip() {
        let s = Session::new(&uuid::Uuid::new_v4().to_string());
        assert_eq!(s.decrypt(&reply(&s)).unwrap().interval_seconds, 42);
    }
    #[test]
    fn debug_trace_redacts_config_and_never_decrypts_unauthenticated_data() {
        let id = uuid::Uuid::new_v4().to_string();
        let s = Session::new(&id);
        let mut response = reply_with_plain(&s, br#"{"mail":{"password":"SYNTHETIC-DO-NOT-LOG-SECRET","sender":"private@example.test","username":"SYNTHETIC-USERNAME"}}"#);
        let mut events = Vec::new();
        s.trace_handshake(Some(&mut |event| events.push(event)));
        s.decrypt_with_trace(&response, Some(&mut |event| events.push(event)))
            .unwrap();
        let log = serde_json::to_string(&events).unwrap();
        for value in [
            &id,
            "SYNTHETIC-DO-NOT-LOG-SECRET",
            "private@example.test",
            "SYNTHETIC-USERNAME",
        ] {
            assert!(!log.contains(value));
        }
        let steps: Vec<_> = events.iter().map(|e| e["step"].as_str().unwrap()).collect();
        let authenticated = steps
            .iter()
            .position(|step| *step == "08.hmac_verified")
            .unwrap();
        let decrypted = steps
            .iter()
            .position(|step| *step == "09.aes_decrypt_and_validate")
            .unwrap();
        assert!(authenticated < decrypted);
        let mut tag = B64.decode(&response.payload.mac).unwrap();
        tag[0] ^= 1;
        response.payload.mac = B64.encode(tag);
        events.clear();
        assert_eq!(
            s.decrypt_with_trace(&response, Some(&mut |event| events.push(event)))
                .err(),
            Some("authentication failed")
        );
        assert!(!events.iter().any(|e| matches!(
            e["step"].as_str(),
            Some("08.hmac_verified" | "09.aes_decrypt_and_validate")
        )));
    }
    #[test]
    fn replay_rejected() {
        let id = uuid::Uuid::new_v4().to_string();
        let s = Session::new(&id);
        let other = Session::new(&id);
        assert!(other.decrypt(&reply(&s)).is_err());
    }
    #[test]
    fn fresh_ephemeral_response() {
        let s = Session::new(&uuid::Uuid::new_v4().to_string());
        let a = reply(&s);
        let b = reply(&s);
        assert_ne!(a.server_public_key, b.server_public_key);
        assert_ne!(a.server_nonce, b.server_nonce);
        assert_ne!(a.payload.ciphertext, b.payload.ciphertext);
    }
    #[test]
    fn tampering_rejected() {
        let s = Session::new(&uuid::Uuid::new_v4().to_string());
        for field in ["mac", "iv", "ciphertext", "nonce"] {
            let mut r = reply(&s);
            let value = match field {
                "mac" => &mut r.payload.mac,
                "iv" => &mut r.payload.iv,
                "ciphertext" => &mut r.payload.ciphertext,
                _ => &mut r.server_nonce,
            };
            let mut bytes = B64.decode(&*value).unwrap();
            bytes[0] ^= 1;
            *value = B64.encode(bytes);
            assert!(s.decrypt(&r).is_err());
        }
    }
    #[test]
    fn configuration_boundaries() {
        for value in [
            "null",
            r#"{"mail":null}"#,
            r#"{"intervalSeconds":0}"#,
            r#"{"batchSize":0}"#,
            r#"{"maxStorageMB":1}"#,
            r#"{"mail":{"enabled":true}}"#,
            r#"{"screenshotDirectory":"relative"}"#,
        ] {
            assert!(Config::parse(value.as_bytes()).is_err())
        }
        let c = Config::parse(b"{}").unwrap();
        assert_eq!(c.batch_size, 10);
        assert!(c.screenshot_directory.is_empty());
    }
    #[test]
    fn profile_validation() {
        let p = Profile::create();
        assert!(p.validate().is_ok());
        let mut bad = Profile::create();
        bad.access_token = "invalid".into();
        assert!(bad.validate().is_err());
    }
    #[test]
    fn url_policy() {
        let p = Profile::create();
        for url in [
            "http://example.com",
            "https://user:password@example.com",
            "https://example.com/#fragment",
        ] {
            assert!(fetch(url, &p).is_err());
        }
    }
    #[test]
    fn ini_conversion() {
        let c=parse_ini("senderMail=sender@example.com\nsmtpServer=smtp.example.com\ntokenCode=synthetic-test-only\ntoMail=recipient@example.com\ntimeInterval=3").unwrap();
        assert_eq!(c.interval_seconds, 180);
        assert!(c.mail.enabled);
    }
}
