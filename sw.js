/* 分享本本 PWA — Service Worker v9
 * 本地資源全量 precache · 可靠背景更新 · 不誤傷同 origin 其他 PWA
 */
const CACHE_PREFIX = 'fenxiang-benben-';
const CACHE = CACHE_PREFIX + 'v9';

const CORE = [
  './',
  './index.html',
  './manifest.json',
  './app.js',
  './alpine.min.js',
  './tailwind-built.css',
  './fa/all.min.css',
  './fa/webfonts/fa-solid-900.woff2',
  './fa/webfonts/fa-regular-400.woff2',
  './fa/webfonts/fa-brands-400.woff2',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/apple-touch-icon.png',
  './favicon.ico',
];

/** 關鍵資源：缺任一項則 install 失敗，瀏覽器稍後重試 */
const CRITICAL = [
  './index.html',
  './app.js',
  './alpine.min.js',
  './tailwind-built.css',
  './fa/all.min.css',
  './fa/webfonts/fa-solid-900.woff2',
];

async function cacheOne(cache, url) {
  try {
    const res = await fetch(url, { cache: 'reload' });
    if (res && res.ok) {
      await cache.put(url, res.clone());
      try {
        await cache.put(new Request(url, { cache: 'reload' }), res.clone());
      } catch (_) {}
      return true;
    }
  } catch (_) {}
  return false;
}

function isNavigation(request) {
  return (
    request.mode === 'navigate' ||
    (request.method === 'GET' &&
      (request.headers.get('accept') || '').includes('text/html'))
  );
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      const results = await Promise.all(CORE.map((u) => cacheOne(cache, u)));
      const failed = CORE.filter((_, i) => !results[i]);
      if (failed.some((u) => CRITICAL.includes(u))) {
        throw new Error('precache failed: ' + failed.join(', '));
      }
      if (failed.length) {
        console.warn('[SW] optional precache missed:', failed.join(', '));
      }
      await self.skipWaiting();
    })()
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(
        keys
          .filter((k) => k.startsWith(CACHE_PREFIX) && k !== CACHE)
          .map((k) => caches.delete(k))
      );
      await self.clients.claim();
    })()
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // 同步建立網路請求並登記 waitUntil（事件仍 active）
  const networkPromise = fetch(req, { cache: 'no-cache' })
    .then(async (res) => {
      if (res && res.status === 200 && res.type === 'basic') {
        try {
          const copy = res.clone();
          const cache = await caches.open(CACHE);
          await cache.put(req, copy);
        } catch (e) {
          console.warn('[SW] cache.put failed', e);
        }
      }
      return res;
    })
    .catch(() => null);

  event.waitUntil(networkPromise.then(() => {}));

  event.respondWith(
    (async () => {
      const cached = await caches.match(req, { cacheName: CACHE });
      if (cached) return cached;

      const net = await networkPromise;
      if (net) return net;

      if (isNavigation(req)) {
        return (
          (await caches.match('./index.html', { cacheName: CACHE })) ||
          (await caches.match('./', { cacheName: CACHE })) ||
          new Response(
            '<!DOCTYPE html><html lang="zh-HK"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>離線</title></head><body style="font-family:system-ui;padding:2rem;text-align:center;background:#fafafa;color:#18181b"><h1>離線</h1><p>請先在有網路時開啟一次完成快取。</p><p style="font-size:12px;color:#71717a">分享本本 · 本機加密密碼管家</p></body></html>',
            { headers: { 'Content-Type': 'text/html; charset=utf-8' } }
          )
        );
      }
      return new Response('Offline', { status: 503, statusText: 'Offline' });
    })()
  );
});

self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});
