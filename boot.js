/**
 * 分享本本 – boot helpers (CSP-safe, no inline script)
 */
(function () {
  /* x-cloak 兜底：腳本載入不完整時避免永久白屏 */
  setTimeout(function () {
    var b = document.body;
    if (!b || !b.hasAttribute('x-cloak')) return;
    b.removeAttribute('x-cloak');
    if (!window.Alpine || typeof passwordManager !== 'function') {
      console.warn('[分享本本] 腳本載入不完整');
      if (!document.getElementById('boot-fail')) {
        var wrap = document.createElement('div');
        wrap.id = 'boot-fail';
        wrap.setAttribute('style', 'position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;padding:1.5rem;background:#fafafa;font-family:system-ui;text-align:center');
        var box = document.createElement('div');
        var h1 = document.createElement('h1');
        h1.textContent = '載入失敗';
        h1.setAttribute('style', 'font-size:1.1rem;margin:0 0 .5rem');
        var p = document.createElement('p');
        p.textContent = '請檢查網路後重新整理';
        p.setAttribute('style', 'font-size:.85rem;color:#71717a;margin:0 0 1rem');
        var btn = document.createElement('button');
        btn.textContent = '重新整理';
        btn.setAttribute('style', 'padding:.6rem 1.2rem;border-radius:999px;border:0;background:#0d9488;color:#fff;font-weight:600;font-size:.85rem;cursor:pointer');
        btn.addEventListener('click', function () { location.reload(); });
        box.appendChild(h1);
        box.appendChild(p);
        box.appendChild(btn);
        wrap.appendChild(box);
        document.body.appendChild(wrap);
      }
    }
  }, 3000);

  /* Service Worker */
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('./sw.js', { updateViaCache: 'none' })
        .then(function (reg) {
          if (reg.waiting) {
            reg.waiting.postMessage('SKIP_WAITING');
          }
          reg.addEventListener('updatefound', function () {
            var nw = reg.installing;
            if (!nw) return;
            nw.addEventListener('statechange', function () {
              if (nw.state === 'installed' && navigator.serviceWorker.controller) {
                console.info('[分享本本] 有新版本可用');
              }
            });
          });
        })
        .catch(function (err) {
          console.warn('[分享本本] SW 註冊失敗', err);
        });
    });
  }
})();
