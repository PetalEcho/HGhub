# 播放协议适配（2026-11-11）

## 范围

首页/剧集的 `api_play(id, ep)` 改为新的播放会话协议。目录、详情、账号和互动仍使用原有入口；帖子视频的新协议适配不在本次范围内。前端仍接收 `PlayInfo.video_url`，但值为本地不透明播放票据，不再是上游签名直链。

旧播放接口会返回业务成功但地址为空；新的响应使用 `streams.main`、`streams.hevc`、`streams.preview`，本次选用主流（H.264），不把预览流当正片、不自动选择 HEVC。

## 传输与安全边界

- `edge_crypto.rs` 实现临时 P-256 ECDH、HKDF-SHA256、方向分离的 AES-256-GCM；认证响应的会话、序列、时间和标签，严格验证编码、结构和大小。没有复制或执行远端 JavaScript。
- 每次获取播放参数使用一个新握手和一次加密请求。不缓存网关密钥，不重放有副作用的 POST，也不在失败后回退到旧明文网关。暂不做跨请求握手复用。
- 网关只访问所选 HTTPS origin，使用既有 DNS/地址安全检查和系统代理；禁止重定向，响应上限 2 MiB，每个网络步骤最多 20 秒。镜像不接收账号凭据，即使关闭严格安全模式也不例外。
- CDN 认证参数只在 Rust 内存中保存。前端得到 `hg://localhost/play/<随机票据>/hls`（Windows/Android 使用原有平台协议基址）。根清单及其子资源由现有 HLS 重写逻辑处理。
- 子资源必须出现在已读取清单中；客户端不能用票据指定任意 URL。对子清单、音轨、初始化分片、密钥和普通分片按角色应用上游认证开关。CDN 认证头仅发给最初媒体 HTTPS origin，跨源跳转不会转发；每一跳继续进行地址/DNS 校验。
- 票据最多保留 32 个，闲置 30 分钟过期，每个票据最多允许 10,000 个清单资源。媒体响应单次上限 32 MiB，20 秒超时。新票据代理目前不复用旧的全局媒体缓存，避免跨身份复用；播放器自身缓冲不变。
- 切线路、账号凭据变化、退出账号及安全模式切换会撤销票据。在途结果检查代次，旧结果不能恢复已撤销的播放。相同账号的资料刷新不会中断播放。
- 网关日志仅写固定阶段、HTTP 状态、线路主机及耗时；错误不含服务器正文、密钥、票据或签名地址。播放自检不再输出原始地址，空地址直接结束，不制造后续 `missing u` 错误。

## 前端恢复

每次进入/重访集数重新取票据，移除无限期播放地址缓存。即使获取地址失败且播放器尚未挂载，也显示“重新加载”。重试重新获取参数，保留已有暂停意图与可恢复的播放位置，丢弃上一集的迟到响应。

## 验证方式

```sh
pnpm build
cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib
BROWSER_EXECUTABLE='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' pnpm test:api-loading
```

离线 Rust 测试覆盖独立 WebCrypto 对照向量、真实临时密钥协商、认证失败、方向隔离、序列/时间/大小边界、内层响应校验、CDN 凭据跨源隔离、清单资源角色、资源数量边界和身份代次。浏览器测试使用真实 React Feed，但 IPC 和媒体渲染器使用替身，不访问外部网络。

显式联网检查（默认忽略）：

```sh
# 仅握手、播放参数和本地票据，不下载视频
cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib playback::tests::live_metadata -- --ignored --nocapture

# 再请求一份 HLS 清单；不请求密钥或音视频分片
HGHUB_TEST_PLAYLIST=1 cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib playback::tests::live_metadata -- --ignored --nocapture
```

本次实测：离线 Rust 测试 55 项通过、6 项联网测试默认忽略；浏览器回归 5 组通过、无外部请求。单独运行新的联网测试后，握手、播放参数、本地票据及携带认证头的根 HLS 清单均通过，清单响应 HTTP 200（重写后 49,372 字节），没有请求密钥或音视频分片。

这些检查不能代替 macOS WKWebView、Windows WebView2、Android/iOS 真机的连续播放、拖动和长时间签名过期验证。上游可能继续变更协议；没有保证所有线路或全部内容可用。若同源 CDN 切到需要携带凭据的跨源域名，本次会失败而不是放宽凭据隔离。
