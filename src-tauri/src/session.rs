//! 会话持久化：token + 用户资料存到应用数据目录。

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Session {
    // 旧版本没有 origin：不能推断其 token 属于哪个镜像，升级后必须重新登录。
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub user: serde_json::Value,
    #[serde(skip)]
    revision: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn credentials_are_bound_to_origin() {
        let store = SessionStore::new();
        store.set(
            "https://huangguoai.com",
            "secret-token".into(),
            json!({"id": 1}),
        );
        assert_eq!(
            store.token("https://huangguoai.com").as_deref(),
            Some("secret-token")
        );
        assert_eq!(store.token("https://huangguoai.ai"), None);
        assert_eq!(store.token("https://evil.example"), None);
        assert!(store.user("https://evil.example").is_null());
        store.clear();
        assert_eq!(store.token("https://huangguoai.com"), None);
    }

    #[test]
    fn identity_generation_survives_guest_and_same_token_roundtrips() {
        let store = SessionStore::new();
        let origin = "https://huangguoai.com";
        let guest = store.snapshot(origin);
        store.set(origin, "token".into(), json!({"id":1}));
        let logged_in = store.snapshot(origin);
        store.set(origin, "token".into(), json!({"id":1,"name":"updated"}));
        assert_eq!(store.snapshot(origin), logged_in);
        store.clear();
        assert_ne!(store.snapshot(origin), guest);
        store.set(origin, "token".into(), json!({"id":1}));
        assert_ne!(store.snapshot(origin), logged_in);
        assert!(serde_json::to_value(store.current.lock().unwrap().clone()).unwrap().get("revision").is_none());
    }

    #[test]
    fn legacy_sessions_are_not_assigned_to_current_line() {
        let store = SessionStore::new();
        *store.current.lock().unwrap() =
            serde_json::from_str(r#"{"token":"legacy","user":{"id":1}}"#).unwrap();
        assert_eq!(store.token("https://huangguoai.com"), None);
        assert!(store.user("https://huangguoai.com").is_null());
    }
}

pub struct SessionStore {
    pub file: Mutex<Option<PathBuf>>,
    pub current: Mutex<Session>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            file: Mutex::new(None),
            current: Mutex::new(Session::default()),
        }
    }

    pub fn bind(&self, dir: PathBuf) {
        let mut path = dir;
        path.push("session.json");
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(sess) = serde_json::from_str::<Session>(&text) {
                *self.current.lock().unwrap() = sess;
            }
        }
        *self.file.lock().unwrap() = Some(path);
    }

    /// Capture identity and its generation under one lock; never persist the generation.
    pub fn snapshot(&self, origin: &str) -> (u64, Option<String>) {
        let cur = self.current.lock().unwrap();
        (cur.revision, (cur.origin == origin && !cur.token.is_empty()).then(|| cur.token.clone()))
    }

    pub fn token(&self, origin: &str) -> Option<String> {
        let cur = self.current.lock().unwrap();
        (cur.origin == origin && !cur.token.is_empty()).then(|| cur.token.clone())
    }

    pub fn user(&self, origin: &str) -> serde_json::Value {
        let cur = self.current.lock().unwrap();
        if cur.origin == origin && !cur.token.is_empty() {
            cur.user.clone()
        } else {
            serde_json::Value::Null
        }
    }

    pub fn set(&self, origin: &str, token: String, user: serde_json::Value) {
        let changed = {
            let mut cur = self.current.lock().unwrap();
            let changed = cur.origin != origin || cur.token != token;
            if changed { cur.revision = cur.revision.wrapping_add(1); }
            cur.origin = origin.to_string();
            cur.token = token;
            cur.user = user;
            changed
        };
        // A profile refresh with the same credential must not interrupt playback.
        if changed { crate::playback::invalidate(); }
        self.persist();
    }

    pub fn clear(&self) {
        {
            let mut cur = self.current.lock().unwrap();
            cur.revision = cur.revision.wrapping_add(1);
            cur.token.clear();
            cur.origin.clear();
            cur.user = serde_json::Value::Null;
        }
        crate::playback::invalidate();
        self.persist();
    }

    fn persist(&self) {
        let snapshot = self.current.lock().unwrap().clone();
        if let Some(path) = self.file.lock().unwrap().as_ref() {
            if let Ok(text) = serde_json::to_string_pretty(&snapshot) {
                let _ = std::fs::write(path, text);
            }
        }
    }
}
