// Fault injection is local only; real React pages + api.call, mocked Tauri IPC.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
import { chromium } from "playwright-core";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const output = join(root, "test-results", "api-loading", new Date().toISOString().replace(/[:.]/g, "-"));
await mkdir(output, { recursive: true });
const report = { transport: "local browser fixture; Tauri IPC mocked", passed: [], external: [] };
let vite, browser, page;
try {
  // Feed state/IPC tests replace only the media renderer: no media is fetched or decoded.
  const surfaceId = "\0fixture-feed-surface.js";
  vite = await createServer({ root, server: { host: "127.0.0.1", port: 0, strictPort: false }, plugins: [{
    name: "fixture-feed-surface", enforce: "pre",
    resolveId(source, importer) {
      if (source === "./VideoSurface" && importer?.endsWith("/src/components/Feed.tsx")) return surfaceId;
    },
    load(id) {
      if (id !== surfaceId) return;
      return `import React, { forwardRef, useImperativeHandle, useRef } from 'react';
        export default forwardRef(function Surface(props, ref) {
          const paused = useRef(!props.autoPlay);
          const fixture = window.apiLoadingFixture;
          fixture.surface = { src: props.src, autoPlay: props.autoPlay, active: props.active };
          fixture.failSurface = value => {
            paused.current = value;
            if (value) props.onPause(); else props.onPlaying();
            props.onError('fixture media failure');
          };
          useImperativeHandle(ref, () => ({
            el: () => ({ paused: paused.current, currentTime: 42 }),
            trace() {}, rate() {}, mute() {}, volume() {}, seek() {}, play() {}, pause() {}, toggle() {},
            reload() { fixture.reloads++; }
          }));
          return React.createElement('div', { 'data-testid': 'video-surface', style: { width: 100, height: 100 } });
        });`;
    },
  }] });
  await vite.listen();
  const origin = vite.resolvedUrls.local[0];
  browser = await chromium.launch({ headless: true, executablePath: process.env.BROWSER_EXECUTABLE || undefined });
  page = await browser.newPage({ viewport: { width: 1100, height: 1200 } });
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.route("**/*", route => {
    const url = route.request().url();
    if (new URL(url).origin === new URL(origin).origin) return route.continue();
    report.external.push(url); return route.abort();
  });
  const complete = (cmd, key, result) => page.evaluate(args => window.apiLoadingFixture.complete(...args), [cmd, key, result]);
  const calls = () => page.evaluate(() => window.apiLoadingFixture.history);
  const visible = async locator => { await locator.waitFor({ state: "visible" }); };

  await page.goto(`${origin}tests/api-loading.html?page=home`);
  await page.waitForFunction(() => window.apiLoadingFixture.history.length === 1);
  await complete("api_feed", "", "404");
  await visible(page.getByText("首页加载失败", { exact: true }));
  await visible(page.getByText(/服务器请求失败（HTTP 404）/));
  assert.equal(await page.locator(".spinner").count(), 0, "Failed home must stop spinning");
  assert(!await page.locator("body").innerText().then(s => s.includes("<html>")), "Hide gateway HTML from UI");
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await page.waitForFunction(() => window.apiLoadingFixture.history.length === 2);
  await complete("api_feed", "", "empty");
  await visible(page.getByText("暂无视频", { exact: true }));
  assert.equal(await page.locator(".spinner").count(), 0);
  report.passed.push("Home: 404 ends loading, readable error, explicit retry, empty result");

  await page.goto(`${origin}tests/api-loading.html`);
  await page.waitForFunction(() => window.apiLoadingFixture.ready);
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal((await calls()).length, 0, "Hidden categories must not prefetch");
  await page.evaluate(() => window.apiLoadingFixture.setActive(true));
  await page.waitForFunction(() => window.apiLoadingFixture.history.length === 5);
  await complete("api_category", "ai-duanju", "item");
  await visible(page.getByText("已加载ai-duanju", { exact: true }));
  await visible(page.getByRole("region", { name: "AI魔改", exact: true }).getByText("加载中…", { exact: true }));
  await complete("api_category", "ai-huanlian", "empty");
  await visible(page.getByRole("region", { name: "AI换脸", exact: true }).getByText("暂无内容", { exact: true }));
  await complete("api_posts", "", "item");
  await visible(page.getByText("已加载api_posts", { exact: true }));
  await complete("api_category", "ai-manju", "503");
  await page.getByRole("button", { name: "重试AI成人漫剧", exact: true }).click();
  await page.waitForFunction(() => window.apiLoadingFixture.history.length === 6);
  await complete("api_category", "ai-manju", "item");
  await visible(page.getByText("已加载ai-manju", { exact: true }));
  assert.equal((await calls()).filter(r => r.args.cate === "ai-duanju").length, 1, "Retry must only reload the failed channel");
  await complete("api_category", "ai-mogai", "404");
  await visible(page.getByRole("button", { name: "重试AI魔改", exact: true }));
  await page.evaluate(() => window.apiLoadingFixture.setActive(false));
  await page.evaluate(() => window.apiLoadingFixture.setActive(true));
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
  assert.equal((await calls()).length, 6, "Revisiting must preserve previews without reloading all channels");
  report.passed.push("Category: defer hidden loading, show successful rows/posts before slow row, independent error/retry, preserve data on revisit");
  const reply = (cmd, value, error = false, episode) => page.evaluate(args => window.apiLoadingFixture.reply(...args), [cmd, value, error, episode]);
  const playCalls = async () => (await calls()).filter(r => r.cmd === "api_play");
  await page.goto(`${origin}tests/api-loading.html?page=feed`);
  await page.waitForFunction(() => window.apiLoadingFixture.history.some(r => r.cmd === "api_play"));
  await reply("api_video", { title: "Fixture", cover: "", episodes: [{ ep_num: 1 }, { ep_num: 2 }], tags: [] });
  await reply("api_play", "fixture playback unavailable", true);
  await visible(page.getByRole("button", { name: "重新加载", exact: true }));
  assert.equal(await page.getByTestId("video-surface").count(), 0, "Initial API failure has no media renderer");
  let previous = (await playCalls()).length;
  await page.getByRole("button", { name: "重新加载", exact: true }).click();
  await page.waitForFunction(n => window.apiLoadingFixture.history.filter(r => r.cmd === "api_play").length > n, previous);
  await reply("api_play", { video_url: "hg://localhost/play/fixture-first/hls" });
  await visible(page.getByTestId("video-surface"));
  assert.equal(await page.evaluate(() => window.apiLoadingFixture.surface.active), false, "Hidden Feed remains inactive after late API response");
  await page.evaluate(() => window.apiLoadingFixture.setActive(true));
  await page.waitForFunction(() => window.apiLoadingFixture.surface.active);
  for (const paused of [true, false]) {
    await page.evaluate(value => window.apiLoadingFixture.failSurface(value), paused);
    previous = (await playCalls()).length;
    await page.getByRole("button", { name: "重新加载", exact: true }).click();
    await page.waitForFunction(n => window.apiLoadingFixture.history.filter(r => r.cmd === "api_play").length > n, previous);
    await reply("api_play", { video_url: `hg://localhost/play/fixture-retry-${paused}/hls` });
    await visible(page.getByTestId("video-surface"));
    assert.equal(await page.evaluate(() => window.apiLoadingFixture.surface.autoPlay), !paused, "Retry preserves paused/playing intent");
  }
  assert.equal(await page.evaluate(() => window.apiLoadingFixture.reloads), 0, "Normal video retries must not reload expired source");
  const pickEpisode = async ep => {
    await page.getByRole("button", { name: "选集", exact: true }).click();
    await page.getByRole("button", { name: String(ep), exact: true }).click();
  };
  previous = (await playCalls()).length;
  await pickEpisode(2);
  await page.waitForFunction(n => window.apiLoadingFixture.history.filter(r => r.cmd === "api_play").length > n, previous);
  await reply("api_play", { video_url: "hg://localhost/play/fixture-second/hls" });
  await visible(page.getByTestId("video-surface"));
  previous = (await playCalls()).length;
  await pickEpisode(1);
  await page.waitForFunction(n => window.apiLoadingFixture.history.filter(r => r.cmd === "api_play").length > n, previous);
  assert.equal(await page.getByTestId("video-surface").count(), 0, "Revisiting an episode must not mount its cached signed source");
  await reply("api_play", { video_url: "hg://localhost/play/fixture-revisited/hls" });
  await visible(page.getByTestId("video-surface"));
  assert.equal(await page.evaluate(() => window.apiLoadingFixture.surface.src), "hg://localhost/play/fixture-revisited/hls");
  previous = (await playCalls()).length;
  await pickEpisode(2);
  await page.waitForFunction(n => window.apiLoadingFixture.history.filter(r => r.cmd === "api_play").length > n, previous);
  previous = (await playCalls()).length;
  await pickEpisode(1);
  await page.waitForFunction(n => window.apiLoadingFixture.history.filter(r => r.cmd === "api_play").length > n, previous);
  await reply("api_play", { video_url: "hg://localhost/play/fixture-current/hls" }, false, 1);
  await visible(page.getByTestId("video-surface"));
  await reply("api_play", { video_url: "hg://localhost/play/fixture-stale/hls" }, false, 2);
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
  assert.equal(await page.evaluate(() => window.apiLoadingFixture.surface.src), "hg://localhost/play/fixture-current/hls", "Late episode response must not replace current source");
  report.passed.push("Feed: API failure retry without surface; fresh tickets on retry/revisit; reject stale responses; preserve pause/active props");

  await page.goto(`${origin}tests/api-loading.html?page=post`);
  await page.waitForFunction(() => window.apiLoadingFixture.history.some(r => r.cmd === "api_post"));
  await reply("api_post", { title: "Post fixture", cover: "", video_url: "hg://localhost/seg?u=fixture", tags: [] });
  await visible(page.getByTestId("video-surface"));
  assert((await calls()).every(r => r.cmd === "api_post"), "Posts must not call normal-video detail/play APIs");
  await page.evaluate(() => window.apiLoadingFixture.failSurface(false));
  await page.getByRole("button", { name: "重新加载", exact: true }).click();
  assert.equal(await page.evaluate(() => window.apiLoadingFixture.reloads), 1, "Posts retain renderer reload behavior");
  report.passed.push("Post: use post source only; keep existing renderer retry");

  await page.goto(`${origin}tests/api-loading.html?page=self-test`);
  await page.waitForFunction(() => window.apiLoadingFixture.ready);
  const runSelfTest = async (info, fail = false) => {
    const before = (await playCalls()).length;
    await page.evaluate(fail => {
      window.selfTestFetches = [];
      window.fetch = async url => {
        window.selfTestFetches.push(String(url));
        if (fail) throw new Error("https://secret.invalid/private-path?token=sentinel-secret");
        if (window.selfTestFetches.length === 1) return new Response(`#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI="${window.apiLoadingFixture.local}/play/sentinel-secret/seg?u=private-key"\n${window.apiLoadingFixture.local}/play/sentinel-secret/seg?u=private-segment\n`, { status: 200 });
        return new Response("fixture", { status: 200 });
      };
      window.selfTestResult = window.apiLoadingFixture.selfTest();
    }, fail);
    await page.waitForFunction(n => window.apiLoadingFixture.history.filter(r => r.cmd === "api_play").length > n, before);
    await reply("api_play", info);
    const result = await page.evaluate(() => window.selfTestResult);
    assert(!/sentinel|private-|secret\.invalid|:\/\/|rustUrl:|inner:/.test(result), "Self-test must not disclose URLs/paths/errors");
    return { result, fetched: await page.evaluate(() => window.selfTestFetches) };
  };
  for (const info of [{}, { video_url: "" }, { video_url: "   " }]) {
    const empty = await runSelfTest(info);
    assert.equal(empty.result, "play:empty");
    assert.deepEqual(empty.fetched, [], "Empty playback response must stop before a missing-u request");
  }
  const local = await page.evaluate(() => window.apiLoadingFixture.local);
  const ticket = `${local}/play/sentinel-secret/hls`;
  const checked = await runSelfTest({ video_url: ticket });
  assert.equal(checked.fetched[0], ticket, "Local playback tickets must not be wrapped again");
  assert.equal(checked.fetched.length, 3, "Only manifest, key, segment; no credential-dropping A/B request");
  assert(checked.fetched.every(url => url.includes("/play/sentinel-secret/")));
  assert(checked.result.includes("keyRust:200/7") && checked.result.includes("seg:200/7"));
  const failed = await runSelfTest({ video_url: ticket }, true);
  assert.equal(failed.result, "play:ok | err:request_failed");
  report.passed.push("Self-test: empty guard, local ticket passthrough, preserve nested ticket routes, redacted diagnostics");
  assert.deepEqual(errors, [], "No page errors");
  assert.deepEqual(report.external, [], "No upstream traffic");
  await page.screenshot({ path: join(output, "final.png"), fullPage: true });
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  report.error = String(error.stack || error);
  await page?.screenshot({ path: join(output, "failure.png"), fullPage: true }).catch(() => {});
  console.error(report.error);
  process.exitCode = 1;
} finally {
  await writeFile(join(output, "report.json"), JSON.stringify(report, null, 2));
  await browser?.close();
  await vite?.close();
  console.log(`Artifacts: ${output}`);
}
