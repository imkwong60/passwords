/**
 * 分享本本 – Secure local password manager
 * AES-GCM + PBKDF2 (120k iterations) · Offline-first
 */
const CRYPTO = {
  PBKDF2_ITERATIONS: 120_000,
  SALT_BYTES: 16,
  IV_BYTES: 12,
  KEY_BITS: 256,
};

function passwordManager() {
  return {
    // ── State ──────────────────────────────────────────────
    passwords: [],
    searchQuery: '',
    isModalOpen: false,
    editingId: null,
    formData: { siteName: '', url: '', username: '', password: '', notes: '' },
    showPasswordInModal: false,
    toasts: [],
    isOnline: navigator.onLine,
    isUnlocked: false,
    isLocked: true,
    hasMasterPassword: false,
    isFirstSetup: false,
    masterPasswordInput: '',
    confirmPasswordInput: '',
    unlockError: '',
    isProcessing: false,
    showMasterPassword: false,
    darkMode: false,
    // Import dialog
    importDialogOpen: false,
    importPreview: [],
    _cryptoKey: null,
    _salt: null,

    // ── Computed ───────────────────────────────────────────
    get filteredPasswords() {
      const q = (this.searchQuery || '').trim().toLowerCase();
      if (!q) return this.passwords;
      return this.passwords.filter(p =>
        (p.siteName || '').toLowerCase().includes(q) ||
        (p.username || '').toLowerCase().includes(q) ||
        (p.notes || '').toLowerCase().includes(q) ||
        (p.url || '').toLowerCase().includes(q)
      );
    },

    // ── Lifecycle ──────────────────────────────────────────
    async init() {
      this._loadTheme();
      window.addEventListener('online', () => this.isOnline = true);
      window.addEventListener('offline', () => this.isOnline = false);
      window.addEventListener('storage', (e) => {
        // 僅在本分頁尚未鎖定時回應，避免 lock() setItem 造成跨 tab 無限 ping-pong
        if (e.key === 'sharebook_lock_signal' && e.newValue && !this.isLocked) {
          this.lock();
        }
      });
      // Lock on page hide / visibility change for better security
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden' && this.isUnlocked) {
          // Soft lock on background is optional; full lock on unload
        }
      });
      await this._bootstrap();
    },

    async _bootstrap() {
      const meta = this._readMeta();
      const plain = localStorage.getItem('passwords'); // legacy plain
      const encrypted = localStorage.getItem('sharebook_vault');

      if (encrypted && meta?.salt) {
        this.hasMasterPassword = true;
        this.isLocked = true;
        this.isUnlocked = false;
        this.isFirstSetup = false;
      } else if (plain) {
        // Migrate path: has unencrypted data
        this.hasMasterPassword = false;
        this.isFirstSetup = true;
        this.isLocked = true;
        this.isUnlocked = false;
        try {
          this.passwords = JSON.parse(plain) || [];
        } catch {
          this.passwords = [];
        }
      } else {
        // Fresh install
        this.hasMasterPassword = false;
        this.isFirstSetup = true;
        this.isLocked = true;
        this.isUnlocked = false;
        this.passwords = [];
      }
    },

    // ── Theme ──────────────────────────────────────────────
    _loadTheme() {
      const saved = localStorage.getItem('sharebook_theme');
      if (saved === 'dark') this.darkMode = true;
      else if (saved === 'light') this.darkMode = false;
      else this.darkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
      this._applyTheme();
    },
    toggleTheme() {
      this.darkMode = !this.darkMode;
      localStorage.setItem('sharebook_theme', this.darkMode ? 'dark' : 'light');
      this._applyTheme();
    },
    _applyTheme() {
      document.documentElement.classList.toggle('dark', this.darkMode);
      document.documentElement.style.colorScheme = this.darkMode ? 'dark' : 'light';
    },

    // ── Crypto helpers ─────────────────────────────────────
    _bufToB64(buf) {
      const bytes = new Uint8Array(buf);
      let s = '';
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s);
    },
    _b64ToBuf(b64) {
      const s = atob(b64);
      const bytes = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
      return bytes.buffer;
    },
    async _deriveKey(password, salt) {
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
      );
      return crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations: CRYPTO.PBKDF2_ITERATIONS,
          hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: CRYPTO.KEY_BITS },
        false,
        ['encrypt', 'decrypt']
      );
    },
    async _encrypt(data, key) {
      const iv = crypto.getRandomValues(new Uint8Array(CRYPTO.IV_BYTES));
      const enc = new TextEncoder();
      const cipher = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        enc.encode(JSON.stringify(data))
      );
      return {
        iv: this._bufToB64(iv),
        data: this._bufToB64(cipher),
      };
    },
    async _decrypt(payload, key) {
      const iv = this._b64ToBuf(payload.iv);
      const data = this._b64ToBuf(payload.data);
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        data
      );
      return JSON.parse(new TextDecoder().decode(plain));
    },

    // ── Meta / vault persistence ───────────────────────────
    _readMeta() {
      try {
        return JSON.parse(localStorage.getItem('sharebook_meta') || 'null');
      } catch { return null; }
    },
    _writeMeta(meta) {
      localStorage.setItem('sharebook_meta', JSON.stringify(meta));
    },
    async _saveVault() {
      if (!this._cryptoKey) return;
      // 剝離 UI-only 欄位，避免污染加密資料模型
      const clean = this.passwords.map(({ _noteOpen, ...rest }) => rest);
      const payload = await this._encrypt(clean, this._cryptoKey);
      localStorage.setItem('sharebook_vault', JSON.stringify(payload));
      // Remove legacy plain storage after successful encrypted save
      localStorage.removeItem('passwords');
    },
    async _loadVault() {
      const raw = localStorage.getItem('sharebook_vault');
      if (!raw || !this._cryptoKey) return [];
      const payload = JSON.parse(raw);
      return await this._decrypt(payload, this._cryptoKey);
    },

    // ── Unlock / Setup ─────────────────────────────────────
    async setupMasterPassword() {
      this.unlockError = '';
      const pw = this.masterPasswordInput.trim();
      const confirm = this.confirmPasswordInput.trim();
      if (pw.length < 8) {
        this.unlockError = '主密碼至少需要 8 個字元';
        return;
      }
      if (pw !== confirm) {
        this.unlockError = '兩次輸入的密碼不一致';
        return;
      }
      this.isProcessing = true;
      try {
        const salt = crypto.getRandomValues(new Uint8Array(CRYPTO.SALT_BYTES));
        this._salt = salt;
        this._cryptoKey = await this._deriveKey(pw, salt);
        this._writeMeta({
          version: 1,
          salt: this._bufToB64(salt),
          iterations: CRYPTO.PBKDF2_ITERATIONS,
          createdAt: Date.now(),
        });
        // Migrate existing plain data (if any) into encrypted vault
        await this._saveVault();
        this.hasMasterPassword = true;
        this.isFirstSetup = false;
        this.isLocked = false;
        this.isUnlocked = true;
        this.masterPasswordInput = '';
        this.confirmPasswordInput = '';
        this.showToast('主密碼已設定，資料已加密保護', 'success');
      } catch (err) {
        console.error(err);
        this.unlockError = '設定失敗，請再試一次';
      } finally {
        this.isProcessing = false;
      }
    },

    async unlock() {
      this.unlockError = '';
      const pw = this.masterPasswordInput;
      if (!pw) {
        this.unlockError = '請輸入主密碼';
        return;
      }
      this.isProcessing = true;
      try {
        const meta = this._readMeta();
        if (!meta?.salt) throw new Error('No meta');
        const salt = this._b64ToBuf(meta.salt);
        this._salt = salt;
        this._cryptoKey = await this._deriveKey(pw, salt);
        this.passwords = await this._loadVault();
        // Ensure each item has a stable id
        this.passwords = this.passwords.map((p, i) => ({
          ...p,
          id: p.id ?? (Date.now() + i),
          _noteOpen: false,
        }));
        this.isLocked = false;
        this.isUnlocked = true;
        this.masterPasswordInput = '';
        this.showToast('已解鎖', 'success');
      } catch (err) {
        console.error(err);
        this._cryptoKey = null;
        this.unlockError = '主密碼錯誤或資料損毀';
      } finally {
        this.isProcessing = false;
      }
    },

    lock() {
      this._cryptoKey = null;
      this.passwords = [];
      this.isUnlocked = false;
      this.isLocked = true;
      this.searchQuery = '';
      this.closeModal();
      this.cancelImport();
      this.masterPasswordInput = '';
      this.unlockError = '';
      // Signal other tabs
      try {
        localStorage.setItem('sharebook_lock_signal', String(Date.now()));
      } catch {}
    },

    // ── CRUD ───────────────────────────────────────────────
    openModal(item = null) {
      if (item) {
        this.editingId = item.id;
        this.formData = {
          siteName: item.siteName || '',
          url: item.url || '',
          username: item.username || '',
          password: item.password || '',
          notes: item.notes || '',
        };
      } else {
        this.editingId = null;
        this.formData = { siteName: '', url: '', username: '', password: '', notes: '' };
      }
      this.showPasswordInModal = false;
      this.isModalOpen = true;
    },
    closeModal() {
      this.isModalOpen = false;
      this.editingId = null;
      this.showPasswordInModal = false;
    },
    async saveItem() {
      const d = this.formData;
      if (!d.siteName?.trim() || !d.username?.trim() || !d.password) {
        this.showToast('請填寫必填欄位', 'error');
        return;
      }
      const wasEditing = this.editingId != null;
      try {
        if (wasEditing) {
          const idx = this.passwords.findIndex(p => p.id === this.editingId);
          if (idx !== -1) {
            this.passwords[idx] = {
              ...this.passwords[idx],
              siteName: d.siteName.trim(),
              url: (d.url || '').trim(),
              username: d.username.trim(),
              password: d.password,
              notes: (d.notes || '').trim(),
            };
          }
        } else {
          this.passwords.unshift({
            id: Date.now() + Math.random(),
            siteName: d.siteName.trim(),
            url: (d.url || '').trim(),
            username: d.username.trim(),
            password: d.password,
            notes: (d.notes || '').trim(),
            createdAt: Date.now(),
            _noteOpen: false,
          });
        }
        await this._saveVault();
        this.closeModal();
        this.showToast(wasEditing ? '已更新' : '已新增', 'success');
      } catch (e) {
        console.error(e);
        this.showToast('儲存失敗：本機儲存空間不足', 'error');
      }
    },
    async deleteItem(id) {
      if (!confirm('確定要刪除此項目？')) return;
      const snapshot = this.passwords;
      try {
        this.passwords = this.passwords.filter(p => p.id !== id);
        await this._saveVault();
        this.showToast('已刪除', 'success');
      } catch (e) {
        console.error(e);
        this.passwords = snapshot;
        this.showToast('刪除失敗：本機儲存空間不足', 'error');
      }
    },
    editItem(item) {
      this.openModal(item);
    },

    // ── Password generator ─────────────────────────────────
    generatePassword() {
      const chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*';
      const len = 18;
      const arr = new Uint8Array(len);
      crypto.getRandomValues(arr);
      let pw = '';
      for (let i = 0; i < len; i++) pw += chars[arr[i] % chars.length];
      this.formData.password = pw;
      this.showPasswordInModal = true;
      this.showToast('已產生隨機密碼', 'success');
    },

    // ── Clipboard ──────────────────────────────────────────
    async copyToClipboard(text, msg = '已複製') {
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        this.showToast(msg, 'success');
      } catch {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;left:-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        this.showToast(msg, 'success');
      }
    },

    // ── Export / Import ────────────────────────────────────
    exportToJson() {
      if (!this.isUnlocked) return;
      const blob = new Blob([JSON.stringify(this.passwords, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `分享本本-備份-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      // Safari / iOS：延遲 revoke，避免下載尚未開始就失效
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      this.showToast('JSON 已匯出', 'success');
    },
    async importFromJson(event) {
      const file = event.target.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        if (!Array.isArray(data)) throw new Error('格式錯誤');
        const mapped = data.map((p, i) => ({
          id: p.id ?? (Date.now() + i + Math.random()),
          siteName: p.siteName || p.site || '',
          url: p.url || '',
          username: p.username || p.user || '',
          password: p.password || '',
          notes: p.notes || '',
          _noteOpen: false,
        })).filter(p => p.siteName && p.username);
        if (mapped.length === 0) {
          this.showToast('檔案內沒有可匯入的項目', 'error');
          event.target.value = '';
          return;
        }
        // 開啟選擇：合併 / 取代
        this.importPreview = mapped;
        this.importDialogOpen = true;
      } catch (e) {
        this.showToast('匯入失敗：檔案格式不正確', 'error');
      }
      event.target.value = '';
    },
    cancelImport() {
      this.importDialogOpen = false;
      this.importPreview = [];
    },
    async confirmImport(mode) {
      // mode: 'merge' | 'replace'
      const mapped = this.importPreview;
      if (!mapped?.length) {
        this.cancelImport();
        return;
      }
      try {
        if (mode === 'replace') {
          this.passwords = mapped;
          await this._saveVault();
          this.showToast(`已取代，共 ${mapped.length} 筆`, 'success');
        } else {
          // 合併：新資料放前面，保留既有
          this.passwords = [...mapped, ...this.passwords];
          await this._saveVault();
          this.showToast(`已合併匯入 ${mapped.length} 筆`, 'success');
        }
      } catch (e) {
        console.error(e);
        this.showToast('匯入失敗：本機儲存空間不足', 'error');
      }
      this.cancelImport();
    },
    exportToHtml() {
      if (!this.isUnlocked) return;
      const rows = this.passwords.map(p => `
        <tr>
          <td>${escapeHtml(p.siteName)}</td>
          <td>${escapeHtml(p.url)}</td>
          <td>${escapeHtml(p.username)}</td>
          <td><code>${escapeHtml(p.password)}</code></td>
          <td>${escapeHtml(p.notes)}</td>
        </tr>`).join('');
      const html = `<!DOCTYPE html><html lang="zh-TW"><head><meta charset="UTF-8"><title>分享本本 匯出</title>
        <style>body{font-family:system-ui;padding:24px;background:#f7f5f0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#0d9488;color:#fff}code{font-family:ui-monospace,monospace}</style></head>
        <body><h1>分享本本 · 匯出 ${new Date().toLocaleString('zh-TW')}</h1>
        <table><thead><tr><th>網站</th><th>網址</th><th>帳號</th><th>密碼</th><th>備註</th></tr></thead>
        <tbody>${rows}</tbody></table></body></html>`;
      const blob = new Blob([html], { type: 'text/html' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `分享本本-${new Date().toISOString().slice(0, 10)}.html`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      this.showToast('HTML 已匯出', 'success');
    },

    // ── Utils ──────────────────────────────────────────────
    safeUrl(url) {
      if (!url) return '#';
      const u = url.trim();
      if (/^https?:\/\//i.test(u)) return u;
      return 'https://' + u;
    },
    showToast(message, type = 'info') {
      const id = Date.now() + Math.random();
      this.toasts.push({ id, message, type });
      setTimeout(() => {
        this.toasts = this.toasts.filter(t => t.id !== id);
      }, 2800);
    },
  };
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
