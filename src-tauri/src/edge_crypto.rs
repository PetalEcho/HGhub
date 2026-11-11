//! Pure dx150-edge-v1 playback cryptography. Transport and endpoint trust are caller concerns.
//! No protocol errors include peer-controlled data, credentials, or key material.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ring::{aead, agreement, hkdf, rand::SystemRandom};
use serde_json::{json, Value};

const ERROR: &str = "Edge protocol validation failed";
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_SEQUENCE: u32 = 16_384;
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_BASE64_BYTES: usize = MAX_BYTES.div_ceil(3) * 4;
const TAG_BYTES: usize = 16;

fn invalid() -> String {
    ERROR.to_owned()
}

/// An ephemeral, single-use P-256 handshake. Deliberately does not implement Debug or Clone.
pub struct Handshake {
    private: agreement::EphemeralPrivateKey,
    public: agreement::PublicKey,
}

impl Handshake {
    pub fn new() -> Result<Self, String> {
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &SystemRandom::new())
                .map_err(|_| invalid())?;
        let public = private.compute_public_key().map_err(|_| invalid())?;
        Ok(Self { private, public })
    }

    pub fn hello(&self) -> Value {
        json!({"v": 1, "type": "hello", "client_pub": URL_SAFE_NO_PAD.encode(self.public.as_ref())})
    }

    pub fn finish(self, hello: &Value, local_now: i64) -> Result<Session, String> {
        validate_envelope(hello, "hello")?;
        let kid = text(hello, "kid")?;
        let sid = text(hello, "sid")?;
        let site = text(hello, "site")?;
        if !identifier(kid, 1, 64) || !identifier(sid, 16, 128) || !valid_site(site) {
            return Err(invalid());
        }
        let server_time = integer_field(hello, "server_time")?;
        let expires_at = integer_field(hello, "expires_at")?;
        let ttl = expires_at.checked_sub(server_time).ok_or_else(invalid)?;
        if !(1..=600).contains(&ttl) {
            return Err(invalid());
        }
        let local_expires_at = local_now.checked_add(ttl).ok_or_else(invalid)?;
        let clock_offset = server_time.checked_sub(local_now).ok_or_else(invalid)?;
        let salt = decode_url(text(hello, "salt")?, 32)?;
        let server_public = decode_url(text(hello, "server_pub")?, 65)?;
        if salt.len() != 32 || server_public.len() != 65 || server_public.first() != Some(&4) {
            return Err(invalid());
        }
        let info = format!("dx150-edge-v1\nplayback\n{site}\n{kid}\n{sid}");
        let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &server_public);
        // ring validates that the peer point is on P-256 and is not the point at infinity.
        let (request_key, response_key) =
            agreement::agree_ephemeral(self.private, &peer, |shared| {
                derive_keys(shared, &salt, &info)
            })
            .map_err(|_| invalid())??;
        Ok(Session {
            request_key: aes_key(&request_key)?,
            response_key,
            info,
            kid: kid.to_owned(),
            sid: sid.to_owned(),
            sequence: 0,
            local_expires_at,
            clock_offset,
        })
    }
}

/// One playback session; mutable access serializes nonce allocation.
pub struct Session {
    request_key: aead::LessSafeKey,
    response_key: [u8; 32],
    info: String,
    kid: String,
    sid: String,
    sequence: u32,
    local_expires_at: i64,
    clock_offset: i64,
}

impl Session {
    pub fn usable(&self, now: i64) -> bool {
        now < self.local_expires_at
            && self.sequence < MAX_SEQUENCE
            && now
                .checked_add(self.clock_offset)
                .is_some_and(is_safe_integer)
    }

    pub fn seal(
        &mut self,
        request: Value,
        token: Option<&str>,
        now: i64,
    ) -> Result<(Value, PendingResponse), String> {
        if !self.usable(now) {
            return Err(invalid());
        }
        let ts = now.checked_add(self.clock_offset).ok_or_else(invalid)?;
        let seq = self.sequence.checked_add(1).ok_or_else(invalid)?;
        let mut inner = json!({"request": request});
        if let Some(token) = token.filter(|token| !token.is_empty()) {
            if token.len() > MAX_BYTES {
                return Err(invalid());
            }
            inner["authorization"] = Value::String(format!("Bearer {token}"));
        }
        let mut ciphertext = serialize_bounded(&inner, MAX_BYTES - TAG_BYTES)?;
        // Consume a sequence before using its nonce, even if encryption were to fail.
        self.sequence = seq;
        self.request_key
            .seal_in_place_append_tag(
                nonce(seq),
                aead::Aad::from(aad(&self.info, "req", seq, ts)),
                &mut ciphertext,
            )
            .map_err(|_| invalid())?;
        let outer = json!({
            "v": 1, "type": "call", "kid": self.kid, "sid": self.sid,
            "seq": seq, "ts": ts, "ciphertext": URL_SAFE_NO_PAD.encode(ciphertext),
        });
        let pending = PendingResponse {
            response_key: self.response_key,
            info: self.info.clone(),
            kid: self.kid.clone(),
            sid: self.sid.clone(),
            seq,
            ts,
        };
        Ok((outer, pending))
    }
}

/// Owns everything needed to authenticate exactly one response, independently of the session.
pub struct PendingResponse {
    response_key: [u8; 32],
    info: String,
    kid: String,
    sid: String,
    seq: u32,
    ts: i64,
}

impl PendingResponse {
    pub fn open(self, result: &Value) -> Result<(u16, Value), String> {
        validate_envelope(result, "result")?;
        if text(result, "kid")? != self.kid
            || text(result, "sid")? != self.sid
            || integer_field(result, "seq")? != i64::from(self.seq)
            || integer_field(result, "ts")? != self.ts
        {
            return Err(invalid());
        }
        let mut ciphertext = decode_url(text(result, "ciphertext")?, MAX_BYTES)?;
        if ciphertext.len() < TAG_BYTES {
            return Err(invalid());
        }
        let key = aes_key(&self.response_key)?;
        let plaintext = key
            .open_in_place(
                nonce(self.seq),
                aead::Aad::from(aad(&self.info, "res", self.seq, self.ts)),
                &mut ciphertext,
            )
            .map_err(|_| invalid())?;
        let inner: Value = serde_json::from_slice(plaintext).map_err(|_| invalid())?;
        let status = integer_field(&inner, "status")?;
        if !(200..=599).contains(&status) {
            return Err(invalid());
        }
        validate_headers(inner.get("headers").ok_or_else(invalid)?)?;
        let encoded_body = text(&inner, "body")?;
        if encoded_body.len() > MAX_BASE64_BYTES {
            return Err(invalid());
        }
        let body = STANDARD.decode(encoded_body).map_err(|_| invalid())?;
        if body.len() > MAX_BYTES {
            return Err(invalid());
        }
        let parsed = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).map_err(|_| invalid())?
        };
        Ok((u16::try_from(status).map_err(|_| invalid())?, parsed))
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}

fn is_safe_integer(value: i64) -> bool {
    (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value)
}

fn integer_field(value: &Value, key: &str) -> Result<i64, String> {
    let value = value.get(key).ok_or_else(invalid)?;
    if let Some(integer) = value.as_i64().filter(|value| is_safe_integer(*value)) {
        return Ok(integer);
    }
    // JSON 1.0 / 1e0 are integers too; do not accept strings, booleans, or rounded unsafe values.
    let number = value.as_f64().ok_or_else(invalid)?;
    if !number.is_finite() || number.fract() != 0.0 || number.abs() > MAX_SAFE_INTEGER as f64 {
        return Err(invalid());
    }
    Ok(number as i64)
}

fn validate_envelope(value: &Value, kind: &str) -> Result<(), String> {
    if integer_field(value, "v")? != 1 || text(value, "type")? != kind {
        return Err(invalid());
    }
    Ok(())
}

fn identifier(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_site(site: &str) -> bool {
    (1..=256).contains(&site.len())
        && site.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'[' | b']' | b'-')
        })
}

fn decode_url(encoded: &str, max: usize) -> Result<Vec<u8>, String> {
    let encoded_limit = max
        .checked_add(2)
        .and_then(|n| (n / 3).checked_mul(4))
        .ok_or_else(invalid)?;
    if encoded.len() > encoded_limit {
        return Err(invalid());
    }
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid())?;
    if decoded.len() > max {
        return Err(invalid());
    }
    Ok(decoded)
}

fn aes_key(bytes: &[u8; 32]) -> Result<aead::LessSafeKey, String> {
    aead::UnboundKey::new(&aead::AES_256_GCM, bytes)
        .map(aead::LessSafeKey::new)
        .map_err(|_| invalid())
}

fn derive_keys(shared: &[u8], salt: &[u8], info: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(shared);
    let derive = |direction: &str| -> Result<[u8; 32], String> {
        let info = format!("{info}\n{direction}");
        let contexts = [info.as_bytes()];
        let okm = prk
            .expand(&contexts, hkdf::HKDF_SHA256)
            .map_err(|_| invalid())?;
        let mut key = [0; 32];
        okm.fill(&mut key).map_err(|_| invalid())?;
        Ok(key)
    };
    Ok((derive("req")?, derive("res")?))
}

fn nonce(seq: u32) -> aead::Nonce {
    let mut bytes = [0; 12];
    bytes[8..].copy_from_slice(&seq.to_be_bytes());
    aead::Nonce::assume_unique_for_key(bytes)
}

fn aad(info: &str, direction: &str, seq: u32, ts: i64) -> String {
    format!("{info}\n{direction}\n{seq}\n{ts}")
}

fn validate_headers(headers: &Value) -> Result<(), String> {
    let headers = headers.as_object().ok_or_else(invalid)?;
    for (name, values) in headers {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(invalid());
        }
        for value in values.as_array().ok_or_else(invalid)? {
            let value = value.as_str().ok_or_else(invalid)?;
            if value
                .bytes()
                .any(|byte| (byte < 32 && byte != b'\t') || byte == 127)
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

// Bound serialization as well as the eventual wire payload, without allocating an unbounded Vec.
fn serialize_bounded(value: &Value, max: usize) -> Result<Vec<u8>, String> {
    struct LimitedWriter {
        bytes: Vec<u8>,
        max: usize,
    }
    impl std::io::Write for LimitedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let length = self
                .bytes
                .len()
                .checked_add(bytes.len())
                .filter(|length| *length <= self.max)
                .ok_or_else(|| std::io::Error::other(ERROR))?;
            self.bytes.reserve(length - self.bytes.len());
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = LimitedWriter {
        bytes: Vec::new(),
        max,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| invalid())?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &str = "dx150-edge-v1\nplayback\nedge.example:443\nkid-1\nsid_0123456789abc";
    const NOW: i64 = 1_700_000_000;
    // Independently generated with Node crypto P-256 (private scalars 1 and 2), then
    // WebCrypto HKDF/SHA-256 and AES-GCM, not this module's implementation.
    // salt = bytes 0..31; nonce = 000000000000000000000001; ts = 1700000000.
    const SERVER_PUBLIC: &str =
        "BHzyexiNA09-ilI4AwS1GsPAiWnid_IbNaYLSPxHZpl4B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E";
    const SHARED: &str = "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg";
    const SALT: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const REQUEST_KEY: &str = "hcM6m39TNxaG3-LlxW5I5Gg4IJhsn_LBnYEWZZhMMmg";
    const RESPONSE_KEY: &str = "_nIUoIHjlYszUvOX6tHQc-5PHXQyNwu7J6gV96uBOMo";
    const REQUEST_PLAIN: &str =
        r#"{"authorization":"Bearer test-token","request":{"method":"GET","path":"/vector"}}"#;
    const REQUEST_CIPHER: &str = "uFePmXtct5UUpSJgqiwZ5cfiYM45FSf-7pjjC3chmBBNofI3MjbnwgUP-j_9MKJqI_fBN66DllbUosFyYOoOSQGir0NLims9tc-ztlSpe8ihoIg3E0gDlAXyhcNWc5gWzg";
    const RESPONSE_CIPHER: &str = "CyQpG3SQVvL4q61QjbzSovHVwXv26VBkkFtuv2l_fHH9QI39XJ2IjI5TfuU4xeveN9dGnJzJYgXs6BhH5EjHYb5qByQ0Pp4Xh9y5JfQgSZ1Rk27hWNe8drg5bEHdLp4pXnBveyT2Q4GT-3v0OsiW_HJ8Gz636aAd1RNNBsTTZk3TznKu70feJ_1y_6VLi_qvmE2-HpNt7MXA";

    fn keys() -> ([u8; 32], [u8; 32]) {
        derive_keys(
            &decode_url(SHARED, 32).unwrap(),
            &decode_url(SALT, 32).unwrap(),
            INFO,
        )
        .unwrap()
    }

    fn session() -> Session {
        let (request, response) = keys();
        Session {
            request_key: aes_key(&request).unwrap(),
            response_key: response,
            info: INFO.to_owned(),
            kid: "kid-1".to_owned(),
            sid: "sid_0123456789abc".to_owned(),
            sequence: 0,
            local_expires_at: NOW + 600,
            clock_offset: 0,
        }
    }

    fn hello() -> Value {
        json!({"v": 1, "type": "hello", "kid": "kid-1", "sid": "sid_0123456789abc",
            "site": "edge.example:443", "server_pub": SERVER_PUBLIC, "salt": SALT,
            "server_time": NOW, "expires_at": NOW + 60})
    }

    fn pending() -> PendingResponse {
        session().seal(Value::Null, None, NOW).unwrap().1
    }

    fn result(pending: &PendingResponse, ciphertext: &str) -> Value {
        json!({"v": 1, "type": "result", "kid": pending.kid, "sid": pending.sid,
            "seq": pending.seq, "ts": pending.ts, "ciphertext": ciphertext})
    }

    fn encrypt(key: &[u8; 32], direction: &str, pending: &PendingResponse, inner: &Value) -> Value {
        let mut bytes = serde_json::to_vec(inner).unwrap();
        aes_key(key)
            .unwrap()
            .seal_in_place_append_tag(
                nonce(pending.seq),
                aead::Aad::from(aad(&pending.info, direction, pending.seq, pending.ts)),
                &mut bytes,
            )
            .unwrap();
        result(pending, &URL_SAFE_NO_PAD.encode(bytes))
    }

    fn inner() -> Value {
        json!({"status": 200, "headers": {"content-type": ["application/json"]},
            "body": STANDARD.encode(br#"{"ok":true}"#)})
    }

    fn assert_invalid<T>(result: Result<T, String>) {
        match result {
            Ok(_) => panic!("expected protocol rejection"),
            Err(error) => assert_eq!(error, ERROR),
        }
    }

    #[test]
    fn independent_webcrypto_hkdf_and_aead_vectors() {
        let (req, res) = keys();
        assert_eq!(URL_SAFE_NO_PAD.encode(req), REQUEST_KEY);
        assert_eq!(URL_SAFE_NO_PAD.encode(res), RESPONSE_KEY);
        assert_ne!(req, res);
        let mut bytes = REQUEST_PLAIN.as_bytes().to_vec();
        aes_key(&req)
            .unwrap()
            .seal_in_place_append_tag(
                nonce(1),
                aead::Aad::from(aad(INFO, "req", 1, NOW)),
                &mut bytes,
            )
            .unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(bytes), REQUEST_CIPHER);
        let pending = pending();
        let response = result(&pending, RESPONSE_CIPHER);
        assert_eq!(
            pending.open(&response).unwrap(),
            (207, json!({"ok": true, "items": [1, "two"]}))
        );
    }

    #[test]
    fn actual_ephemeral_handshake_and_clock_offset_interoperate() {
        let handshake = Handshake::new().unwrap();
        let client_hello = handshake.hello();
        assert_eq!(client_hello["v"], 1);
        assert_eq!(client_hello["type"], "hello");
        assert_eq!(client_hello.as_object().unwrap().len(), 3);
        let client_public = decode_url(client_hello["client_pub"].as_str().unwrap(), 65).unwrap();
        assert_eq!(client_public.len(), 65);
        assert_eq!(client_public[0], 4);
        assert_ne!(handshake.hello(), Handshake::new().unwrap().hello());
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &SystemRandom::new())
                .unwrap();
        let mut server_hello = hello();
        server_hello["server_pub"] =
            json!(URL_SAFE_NO_PAD.encode(private.compute_public_key().unwrap().as_ref()));
        let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, client_public);
        let (req, res) = agreement::agree_ephemeral(private, &peer, |shared| {
            derive_keys(shared, &decode_url(SALT, 32).unwrap(), INFO).unwrap()
        })
        .unwrap();
        let mut session = handshake.finish(&server_hello, NOW - 100).unwrap();
        assert_eq!(session.local_expires_at, NOW - 40);
        let (call, pending) = session
            .seal(json!({"path": "/vector"}), Some("secret"), NOW - 99)
            .unwrap();
        assert_eq!(call["seq"], 1);
        assert_eq!(call["ts"], NOW + 1);
        let mut ciphertext = decode_url(call["ciphertext"].as_str().unwrap(), MAX_BYTES).unwrap();
        let key = aes_key(&req).unwrap();
        let plain = key
            .open_in_place(
                nonce(1),
                aead::Aad::from(aad(INFO, "req", 1, NOW + 1)),
                &mut ciphertext,
            )
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(plain).unwrap(),
            json!({"request": {"path": "/vector"}, "authorization": "Bearer secret"})
        );
        let response = encrypt(&res, "res", &pending, &inner());
        // A pending response remains usable after its Session has been discarded.
        drop(session);
        assert_eq!(pending.open(&response).unwrap(), (200, json!({"ok": true})));
    }

    #[test]
    fn absent_and_empty_tokens_are_omitted() {
        for token in [None, Some("")] {
            let (call, _) = session().seal(json!({"x": 1}), token, NOW).unwrap();
            let mut bytes = decode_url(call["ciphertext"].as_str().unwrap(), MAX_BYTES).unwrap();
            let key = aes_key(&keys().0).unwrap();
            let plaintext = key
                .open_in_place(
                    nonce(1),
                    aead::Aad::from(aad(INFO, "req", 1, NOW)),
                    &mut bytes,
                )
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(plaintext).unwrap(),
                json!({"request": {"x": 1}})
            );
        }
    }

    #[test]
    fn malformed_server_hellos_are_rejected_generically() {
        let bad_fields = [
            ("v", json!(2)),
            ("v", json!("1")),
            ("type", json!("call")),
            ("kid", json!("")),
            ("kid", json!("a".repeat(65))),
            ("kid", json!("bad\nkid")),
            ("sid", json!("short")),
            ("sid", json!("a".repeat(129))),
            ("sid", json!("sid/0123456789abc")),
            ("site", json!("")),
            ("site", json!("a".repeat(257))),
            ("site", json!("https://example.com")),
            ("site", json!("example_1")),
            ("site", json!("例.com")),
            ("site", json!("example\r\n")),
            ("server_time", json!("1700000000")),
            ("server_time", json!(1.5)),
            ("server_time", json!(MAX_SAFE_INTEGER + 1)),
            ("expires_at", json!(-MAX_SAFE_INTEGER - 1)),
            ("expires_at", json!(NOW)),
            ("expires_at", json!(NOW - 1)),
            ("expires_at", json!(NOW + 601)),
            ("salt", json!(format!("{SALT}="))),
            ("salt", json!(URL_SAFE_NO_PAD.encode([0; 31]))),
            ("salt", json!(URL_SAFE_NO_PAD.encode([0; 33]))),
            ("salt", json!("!".repeat(43))),
            ("server_pub", json!(URL_SAFE_NO_PAD.encode([0; 65]))),
            ("server_pub", json!(URL_SAFE_NO_PAD.encode([4; 65]))),
            ("server_pub", json!(URL_SAFE_NO_PAD.encode([4; 64]))),
            ("server_pub", json!(URL_SAFE_NO_PAD.encode([2; 33]))),
        ];
        for (field, value) in bad_fields {
            let mut hello = hello();
            hello[field] = value;
            assert_invalid(Handshake::new().unwrap().finish(&hello, NOW));
        }
        for field in [
            "v",
            "type",
            "kid",
            "sid",
            "site",
            "server_time",
            "expires_at",
            "salt",
            "server_pub",
        ] {
            let mut hello = hello();
            hello.as_object_mut().unwrap().remove(field);
            assert_invalid(Handshake::new().unwrap().finish(&hello, NOW));
        }
        assert_invalid(Handshake::new().unwrap().finish(&Value::Null, NOW));
        assert_invalid(Handshake::new().unwrap().finish(&hello(), i64::MAX));
        assert_invalid(Handshake::new().unwrap().finish(&hello(), i64::MIN));
    }

    #[test]
    fn hello_boundaries_and_safe_integer_times() {
        for ttl in [1, 600] {
            let mut hello = hello();
            hello["kid"] = json!("K_9-".repeat(16));
            hello["sid"] = json!("S_9-".repeat(32));
            hello["site"] = json!("a.:[9]-0".repeat(32));
            hello["expires_at"] = json!(NOW + ttl);
            let session = Handshake::new().unwrap().finish(&hello, NOW).unwrap();
            assert!(session.usable(NOW + ttl - 1));
            assert!(!session.usable(NOW + ttl));
        }
        let mut hello = hello();
        hello["server_time"] = json!(MAX_SAFE_INTEGER - 1);
        hello["expires_at"] = json!(MAX_SAFE_INTEGER);
        assert!(Handshake::new().unwrap().finish(&hello, NOW).is_ok());
        assert_eq!(integer_field(&json!({"n": 1.0}), "n").unwrap(), 1);
        for n in [
            json!(true),
            json!(null),
            json!(1.25),
            json!(u64::MAX),
            json!("1"),
        ] {
            assert_invalid(integer_field(&json!({"n": n}), "n"));
        }
    }

    #[test]
    fn expiry_sequence_and_checked_arithmetic() {
        let mut session = session();
        assert!(session.usable(NOW));
        assert!(!session.usable(NOW + 600));
        assert_invalid(session.seal(Value::Null, None, NOW + 600));
        assert_eq!(session.sequence, 0);
        session.sequence = MAX_SEQUENCE - 1;
        let (call, pending) = session.seal(Value::Null, None, NOW).unwrap();
        assert_eq!(call["seq"], MAX_SEQUENCE);
        assert!(!session.usable(NOW));
        assert_invalid(session.seal(Value::Null, None, NOW));
        let response = encrypt(&keys().1, "res", &pending, &inner());
        assert!(pending.open(&response).is_ok());
        session.sequence = u32::MAX;
        assert_invalid(session.seal(Value::Null, None, NOW));
        session.sequence = 0;
        session.clock_offset = i64::MIN;
        assert!(!session.usable(-1));
        assert_invalid(session.seal(Value::Null, None, -1));
        session.clock_offset = MAX_SAFE_INTEGER;
        assert!(!session.usable(NOW));
        session.clock_offset = i64::MAX;
        assert!(!session.usable(NOW));
    }

    #[test]
    fn response_metadata_and_ciphertext_tampering_fail() {
        for (field, value) in [
            ("v", json!(2)),
            ("type", json!("call")),
            ("kid", json!("kid-2")),
            ("sid", json!("sid_0123456789abd")),
            ("seq", json!(0)),
            ("seq", json!(2)),
            ("seq", json!(1.5)),
            ("ts", json!(NOW + 1)),
            ("ts", json!("1700000000")),
            ("ciphertext", json!("")),
            ("ciphertext", json!("!")),
            ("ciphertext", json!(format!("{RESPONSE_CIPHER}="))),
        ] {
            let pending = pending();
            let mut response = result(&pending, RESPONSE_CIPHER);
            response[field] = value;
            assert_invalid(pending.open(&response));
        }
        for field in ["v", "type", "kid", "sid", "seq", "ts", "ciphertext"] {
            let pending = pending();
            let mut response = result(&pending, RESPONSE_CIPHER);
            response.as_object_mut().unwrap().remove(field);
            assert_invalid(pending.open(&response));
        }
        let original = decode_url(RESPONSE_CIPHER, MAX_BYTES).unwrap();
        // Both encrypted payload and authentication tag must be protected.
        for index in [0, original.len() - 1] {
            let pending = pending();
            let mut bytes = original.clone();
            bytes[index] ^= 1;
            let response = result(&pending, &URL_SAFE_NO_PAD.encode(bytes));
            assert_invalid(pending.open(&response));
        }
    }

    #[test]
    fn directions_and_session_context_cannot_be_swapped() {
        let (req, res) = keys();
        for (key, direction) in [(req, "req"), (req, "res"), (res, "req")] {
            let pending = pending();
            let response = encrypt(&key, direction, &pending, &inner());
            assert_invalid(pending.open(&response));
        }
        for other_info in [
            INFO.replace("playback", "account"),
            INFO.replace("edge.example:443", "other.example"),
        ] {
            let mut pending = pending();
            let response = encrypt(&res, "res", &pending, &inner());
            pending.info = other_info;
            assert_invalid(pending.open(&response));
        }
    }

    #[test]
    fn authenticated_inner_structure_is_still_validated() {
        for (field, value) in [
            ("status", json!(199)),
            ("status", json!(600)),
            ("status", json!(200.5)),
            ("status", json!("200")),
            ("headers", json!(null)),
            ("headers", json!([])),
            ("headers", json!({"": []})),
            ("headers", json!({"bad name": ["x"]})),
            ("headers", json!({"bad:name": ["x"]})),
            ("headers", json!({"bad\r\nname": ["x"]})),
            ("headers", json!({"ü": []})),
            ("headers", json!({"x": "not-an-array"})),
            ("headers", json!({"x": [42]})),
            ("headers", json!({"x": ["line\rbreak"]})),
            ("headers", json!({"x": ["line\nbreak"]})),
            ("headers", json!({"x": ["nul\u{0}"]})),
            ("body", json!(42)),
            ("body", json!("_w")),
            ("body", json!("/w==")),
            ("body", json!(STANDARD.encode(b"not JSON"))),
        ] {
            let pending = pending();
            let mut inner = inner();
            inner[field] = value;
            let response = encrypt(&keys().1, "res", &pending, &inner);
            assert_invalid(pending.open(&response));
        }
        for field in ["status", "headers", "body"] {
            let pending = pending();
            let mut inner = inner();
            inner.as_object_mut().unwrap().remove(field);
            let response = encrypt(&keys().1, "res", &pending, &inner);
            assert_invalid(pending.open(&response));
        }
    }

    #[test]
    fn empty_bodies_and_http_status_boundaries_are_supported() {
        for status in [200, 204, 599] {
            let pending = pending();
            let inner = json!({"status": status, "headers": {"x-valid": ["", "a\tb"], "empty": []}, "body": ""});
            let response = encrypt(&keys().1, "res", &pending, &inner);
            assert_eq!(pending.open(&response).unwrap(), (status, Value::Null));
        }
    }

    #[test]
    fn encoded_and_decoded_size_limits_are_enforced() {
        let mut session = session();
        assert_invalid(session.seal(json!("x".repeat(MAX_BYTES)), None, NOW));
        assert_invalid(session.seal(json!("\n".repeat(MAX_BYTES / 2)), None, NOW));
        assert_invalid(session.seal(Value::Null, Some(&"x".repeat(MAX_BYTES + 1)), NOW));
        assert_eq!(session.sequence, 0);
        assert!(serialize_bounded(&json!("x"), 3).is_ok());
        assert_invalid(serialize_bounded(&json!("x"), 2));
        assert!(decode_url(&URL_SAFE_NO_PAD.encode(vec![0; MAX_BYTES]), MAX_BYTES).is_ok());
        assert_invalid(decode_url(
            &URL_SAFE_NO_PAD.encode(vec![0; MAX_BYTES + 1]),
            MAX_BYTES,
        ));
        let pending = pending();
        let response = result(&pending, &"A".repeat(MAX_BASE64_BYTES + 1));
        assert_invalid(pending.open(&response));
    }
}
