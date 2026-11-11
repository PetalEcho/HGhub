//! Ephemeral playback gateway sessions and Rust-only media capabilities.
//! No signed URL, CDN credential, gateway key or session is persisted.
use crate::{edge_crypto::Handshake, net, network_policy};
use base64::{engine::general_purpose::STANDARD, Engine};
use once_cell::sync::Lazy;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};
use tauri::http::Response;

static GENERATION: AtomicU64 = AtomicU64::new(0);
static TICKETS: Lazy<Mutex<HashMap<String, Ticket>>> = Lazy::new(|| Mutex::new(HashMap::new()));
const IDLE_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_TICKETS: usize = 32;
const MAX_RESOURCES: usize = 10000;

#[derive(Clone)]
struct Ticket {
    root: String,
    origin: String,
    line: String,
    strict: bool,
    generation: u64,
    touched: Instant,
    headers: reqwest::header::HeaderMap,
    manifests: bool,
    segments: bool,
    allowed: HashSet<String>,
    playlist_urls: HashSet<String>,
}

impl Ticket {
    fn rewrite(&mut self, base: &str, text: &str, prefix: &str) -> Result<String, String> {
        let rewritten = crate::media::rewrite_playlist(base, text, prefix);
        let segment_prefix = format!("{prefix}/seg?u=");
        let mut next_is_playlist = false;
        for line in rewritten.lines() {
            let playlist_attribute = line.starts_with("#EXT-X-MEDIA:")
                || line.starts_with("#EXT-X-I-FRAME-STREAM-INF:")
                || line.starts_with("#EXT-X-RENDITION-REPORT:");
            for part in line.split('"') {
                if let Some(encoded) = part.strip_prefix(&segment_prefix) {
                    let decoded = percent_encoding::percent_decode_str(encoded)
                        .decode_utf8()
                        .map_err(|_| "播放清单地址无效")?
                        .into_owned();
                    if !self.allowed.contains(&decoded) && self.allowed.len() >= MAX_RESOURCES {
                        return Err("播放清单资源过多".into());
                    }
                    if next_is_playlist
                        || playlist_attribute
                        || url::Url::parse(&decoded).is_ok_and(|u| u.path().ends_with(".m3u8"))
                    {
                        self.playlist_urls.insert(decoded.clone());
                    }
                    self.allowed.insert(decoded);
                }
            }
            if line.starts_with("#EXT-X-STREAM-INF:") {
                next_is_playlist = true;
            } else if !line.is_empty() && !line.starts_with('#') {
                next_is_playlist = false;
            }
        }
        Ok(rewritten)
    }
}

pub(crate) fn invalidate() {
    GENERATION.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut tickets) = TICKETS.lock() {
        tickets.clear();
    }
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

async fn request(origin: &str, token: Option<&str>, id: i64, ep: u32) -> Result<Value, String> {
    if id <= 0 || ep == 0 || ep > i32::MAX as u32 {
        return Err("播放编号无效".into());
    }
    let origin = net::normalize_base(origin).ok_or("播放线路无效")?;
    // Mirrors never receive credentials, even with relaxed destination validation.
    if token.is_some() && !net::trusted_auth_origin(&origin) {
        return Err("镜像线路仅供游客浏览".into());
    }
    // One fresh session per preparation: no cross-identity key reuse and no replay of POSTs.
    let handshake = Handshake::new()?;
    let hello = net::playback_post(&origin, &handshake.hello()).await?;
    let mut session = handshake.finish(&hello, now())?;
    let logical = json!({"method":"POST", "path":format!("/api/videos/{id}/episodes/{ep}/playback"),
        "body":STANDARD.encode(b"{}"), "content_type":"application/json"});
    let (packet, pending) = session.seal(logical, token, now())?;
    let result = net::playback_post(&origin, &packet).await?;
    let (status, body) = pending.open(&result)?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status}：获取播放参数失败"));
    }
    if body.get("status").and_then(Value::as_i64) != Some(1)
        && body.get("code").and_then(Value::as_i64) != Some(200)
    {
        return Err("上游未提供可用的播放参数".into());
    }
    body.get("data")
        .cloned()
        .ok_or_else(|| "播放参数为空".into())
}

fn stream_url(data: &Value) -> Result<&str, String> {
    if data.get("manifest_method").and_then(Value::as_str) != Some("GET") {
        return Err("不支持的播放清单请求方式".into());
    }
    data.pointer("/streams/main")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "播放参数缺少 H.264 地址".into())
}

fn cdn_headers(data: &Value) -> Result<reqwest::header::HeaderMap, String> {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    let mut headers = HeaderMap::new();
    let cdn = &data["cdn"];
    if cdn["m3u8Enabled"] == true || cdn["otherEnabled"] == true {
        let name = cdn["authKey"]
            .as_str()
            .ok_or("CDN 参数无效")?
            .to_ascii_lowercase();
        // Do not let upstream set routing, cookie, proxy or account-auth headers.
        if !name.starts_with("x-")
            || name.starts_with("x-forwarded-")
            || name.starts_with("x-http-")
            || name == "x-cdn-app"
        {
            return Err("CDN 认证头不受支持".into());
        }
        let value = cdn["authValue"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 4096)
            .ok_or("CDN 参数无效")?;
        let app = cdn["app"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or("CDN 参数无效")?;
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| "CDN 参数无效")?,
            HeaderValue::from_str(value).map_err(|_| "CDN 参数无效")?,
        );
        headers.insert(
            "x-cdn-app",
            HeaderValue::from_str(app).map_err(|_| "CDN 参数无效")?,
        );
    }
    Ok(headers)
}

fn register(data: &Value, line: &str, generation: u64) -> Result<String, String> {
    let root = stream_url(data)?;
    let parsed = network_policy::parse_target(root).map_err(|_| "播放地址未通过安全校验")?;
    if parsed.scheme() != "https" {
        return Err("播放地址必须使用 HTTPS".into());
    }
    let headers = cdn_headers(data)?;
    let mut random = [0u8; 24];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "无法创建播放会话")?;
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
    let ticket = Ticket {
        root: root.into(),
        origin: parsed.origin().ascii_serialization(),
        line: line.into(),
        strict: network_policy::strict_security(),
        generation,
        touched: Instant::now(),
        headers,
        manifests: data["cdn"]["m3u8Enabled"] == true,
        segments: data["cdn"]["otherEnabled"] == true,
        allowed: HashSet::from([root.to_string()]),
        playlist_urls: HashSet::from([root.to_string()]),
    };
    let mut tickets = TICKETS.lock().map_err(|_| "播放会话锁失败")?;
    if generation != GENERATION.load(Ordering::SeqCst) {
        return Err("登录状态或线路已变化，请重试".into());
    }
    tickets.retain(|_, v| v.touched.elapsed() < IDLE_TTL);
    if tickets.len() >= MAX_TICKETS {
        if let Some(oldest) = tickets
            .iter()
            .min_by_key(|(_, t)| t.touched)
            .map(|(k, _)| k.clone())
        {
            tickets.remove(&oldest);
        }
    }
    tickets.insert(id.clone(), ticket);
    Ok(format!("{}/play/{id}/hls", crate::media::LOCAL_ORIGIN))
}

pub(crate) async fn prepare(
    origin: &str,
    token: Option<&str>,
    id: i64,
    ep: u32,
) -> Result<Value, String> {
    let generation = GENERATION.load(Ordering::SeqCst);
    let data = request(origin, token, id, ep).await?;
    let local_url = register(&data, origin, generation)?;
    Ok(json!({"id":id, "ep_num":ep, "duration":0, "title":"", "video_url":local_url}))
}

fn response(status: u16, mime: &str, bytes: Vec<u8>) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("Content-Type", mime)
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(bytes)
        .unwrap_or_else(|_| Response::new(Vec::new()))
}

pub(crate) async fn handle(path: &str, query: &str) -> Response<Vec<u8>> {
    match serve(path, query).await {
        Ok((mime, bytes)) => response(200, &mime, bytes),
        Err(_) => response(
            502,
            "text/plain",
            b"playback resource unavailable; refresh playback".to_vec(),
        ),
    }
}

async fn serve(path: &str, query: &str) -> Result<(String, Vec<u8>), String> {
    let (id, route) = path
        .strip_prefix("/play/")
        .and_then(|p| p.split_once('/'))
        .ok_or("播放资源无效")?;
    if !matches!(route, "hls" | "seg") {
        return Err("播放资源无效".into());
    }
    let (ticket, target) = {
        let mut tickets = TICKETS.lock().map_err(|_| "播放会话锁失败")?;
        let t = tickets.get_mut(id).ok_or("播放会话已失效")?;
        if t.touched.elapsed() >= IDLE_TTL
            || t.generation != GENERATION.load(Ordering::SeqCst)
            || t.line != net::base()
            || t.strict != network_policy::strict_security()
        {
            return Err("播放会话已失效".into());
        }
        let target = if route == "hls" {
            t.root.clone()
        } else {
            url::form_urlencoded::parse(query.as_bytes())
                .find(|(k, _)| k == "u")
                .map(|(_, v)| v.into_owned())
                .ok_or("播放资源无效")?
        };
        if !t.allowed.contains(&target) {
            return Err("播放资源未授权".into());
        }
        t.touched = Instant::now();
        (t.clone(), target)
    };
    let is_manifest = ticket.playlist_urls.contains(&target);
    let auth = if (ticket.manifests && is_manifest) || (ticket.segments && !is_manifest) {
        ticket.headers.clone()
    } else {
        reqwest::header::HeaderMap::new()
    };
    let (mime, bytes, final_url) =
        net::playback_bytes(&target, &ticket.origin, &ticket.line, auth).await?;
    if ticket.generation != GENERATION.load(Ordering::SeqCst) {
        return Err("播放会话已失效".into());
    }
    let is_playlist = route == "hls"
        || mime.to_ascii_lowercase().contains("mpegurl")
        || bytes.starts_with(b"#EXTM3U")
        || bytes.starts_with(b"\xef\xbb\xbf#EXTM3U");
    if !is_playlist {
        return Ok((mime, bytes));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "播放清单编码无效")?;
    if !text.trim_start_matches('\u{feff}').starts_with("#EXTM3U") {
        return Err("播放清单格式无效".into());
    }
    let prefix = format!("{}/play/{id}", crate::media::LOCAL_ORIGIN);
    let mut tickets = TICKETS.lock().map_err(|_| "播放会话锁失败")?;
    let current = tickets.get_mut(id).ok_or("播放会话已失效")?;
    let rewritten = current.rewrite(&final_url, text, &prefix)?;
    Ok((
        "application/vnd.apple.mpegurl".into(),
        rewritten.into_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "manual metadata-only probe; never downloads media"]
    async fn live_metadata() {
        let data = request(net::DEFAULT_BASE, None, 117, 3)
            .await
            .expect("playback metadata");
        fn shape(v: &Value) -> Value {
            match v {
                Value::Object(m) => {
                    Value::Object(m.iter().map(|(k, v)| (k.clone(), shape(v))).collect())
                }
                Value::Array(a) => Value::Array(a.iter().map(shape).collect()),
                Value::String(s) => json!({"type":"string","nonempty":!s.is_empty()}),
                Value::Bool(b) => json!(b),
                _ => json!("number_or_null"),
            }
        }
        println!("metadata shape: {}", shape(&data));
        assert_eq!(data["manifest_method"], "GET");
        let _ = stream_url(&data).expect("H264 stream");
        let _ = cdn_headers(&data).expect("CDN headers");
        let local = register(&data, net::DEFAULT_BASE, GENERATION.load(Ordering::SeqCst))
            .expect("local playback ticket");
        assert!(local.starts_with(&format!("{}/play/", crate::media::LOCAL_ORIGIN)));
        assert!(!local.contains("?"));
        // Opt-in manifest-only validation: never fetch keys or audio/video fragments.
        if std::env::var("HGHUB_TEST_PLAYLIST").as_deref() == Ok("1") {
            let path = local.strip_prefix(crate::media::LOCAL_ORIGIN).unwrap();
            let manifest = handle(path, "").await;
            assert_eq!(manifest.status(), 200, "proxied manifest status");
            assert!(manifest.body().starts_with(b"#EXTM3U"));
            println!(
                "manifest valid; bytes={}; no fragments fetched",
                manifest.body().len()
            );
        }
        invalidate();
    }
    fn fixture_ticket() -> Ticket {
        let root = "https://cdn.example/master.m3u8".to_string();
        Ticket {
            root: root.clone(),
            origin: "https://cdn.example".into(),
            line: "https://site.example".into(),
            strict: true,
            generation: 0,
            touched: Instant::now(),
            headers: reqwest::header::HeaderMap::new(),
            manifests: true,
            segments: true,
            allowed: HashSet::from([root.clone()]),
            playlist_urls: HashSet::from([root]),
        }
    }

    #[test]
    fn nested_resource_roles_and_ticket_prefix_are_preserved() {
        let mut ticket = fixture_ticket();
        let prefix = "hg://localhost/play/synthetic-ticket";
        let root = ticket.root.clone();
        let master = ticket.rewrite(&root, "#EXTM3U\n#EXT-X-MEDIA:TYPE=AUDIO,URI=\"audio\"\n#EXT-X-STREAM-INF:BANDWIDTH=1000\nvideo\n", prefix).unwrap();
        assert!(master.contains("hg://localhost/play/synthetic-ticket/seg?u="));
        assert!(ticket.playlist_urls.contains("https://cdn.example/video"));
        assert!(ticket.playlist_urls.contains("https://cdn.example/audio"));
        let child = ticket.rewrite("https://cdn.example/video", "#EXTM3U\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXT-X-KEY:METHOD=AES-128,URI=\"key\"\n#EXTINF:2,\nsegment\n#EXT-X-ENDLIST\n", prefix).unwrap();
        assert!(child.contains("/play/synthetic-ticket/seg?u="));
        for resource in ["init.mp4", "key", "segment"] {
            let resource = format!("https://cdn.example/{resource}");
            assert!(ticket.allowed.contains(&resource));
            assert!(!ticket.playlist_urls.contains(&resource));
        }
        assert!(!ticket.allowed.contains("https://other.example/secret"));
    }

    #[test]
    fn resource_limit_does_not_reject_existing_urls() {
        let mut ticket = fixture_ticket();
        ticket
            .allowed
            .extend((1..MAX_RESOURCES).map(|i| format!("https://cdn.example/{i}")));
        assert_eq!(ticket.allowed.len(), MAX_RESOURCES);
        assert!(ticket
            .rewrite(
                "https://cdn.example/master.m3u8",
                "#EXTM3U\n1\n",
                "hg://localhost/play/test"
            )
            .is_ok());
        assert!(ticket
            .rewrite(
                "https://cdn.example/master.m3u8",
                "#EXTM3U\nnew\n",
                "hg://localhost/play/test"
            )
            .is_err());
    }

    #[tokio::test]
    async fn invalid_input_and_mirror_credentials_fail_before_network() {
        assert!(request(net::DEFAULT_BASE, None, 0, 1).await.is_err());
        assert!(request(net::DEFAULT_BASE, None, 1, 0).await.is_err());
        assert!(request("https://mirror.example", Some("secret"), 1, 1)
            .await
            .is_err());
        assert!(
            serve("/play/nonexistent/seg", "u=https%3A%2F%2Fexample.com")
                .await
                .is_err()
        );
    }

    #[test]
    fn invalid_payloads_fail_closed() {
        assert_eq!(stream_url(&json!({"manifest_method":"GET","streams":{"main":"https://cdn.example/main.m3u8","preview":"https://cdn.example/preview.m3u8"}})).unwrap(), "https://cdn.example/main.m3u8");
        assert!(stream_url(&json!({"manifest_method":"GET","streams":{"main":""}})).is_err());
        assert!(stream_url(
            &json!({"manifest_method":"POST","streams":{"h264":"https://example.com/a"}})
        )
        .is_err());
        for key in [
            "Authorization",
            "Cookie",
            "Host",
            "x-forwarded-for",
            "x-http-method-override",
            "x-cdn-app",
            "x-bad\r\n",
        ] {
            assert!(cdn_headers(
                &json!({"cdn":{"m3u8Enabled":true,"authKey":key,"authValue":"secret","app":"test"}})
            )
            .is_err());
        }
        assert!(cdn_headers(&json!({"cdn":{"m3u8Enabled":true,"authKey":"x-media-token","authValue":"bad\r\n","app":"test"}})).is_err());
        assert_eq!(
            cdn_headers(&json!({"cdn":{"m3u8Enabled":false,"otherEnabled":false}}))
                .unwrap()
                .len(),
            0
        );
    }
}
