/**
 * 分享本本 – Secure local password manager
 * AES-GCM + PBKDF2 (120k iterations) · Offline-first
 * + Supabase Email 登入與 app_data 同步
 */
const CRYPTO = {
  PBKDF2_ITERATIONS: 120_000,
  SALT_BYTES: 16,
  IV_BYTES: 12,
  KEY_BITS: 256,
};

const SUPABASE_URL = 'https://wanknivxcsrasdkkxmfr.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndhbmtuaXZ4Y3NyYXNka2t4bWZyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODczMzE4NjcsImV4cCI6MjEwMjkwNzg2N30.tqsFimERtYCxoh8J-8FlqxByWtX2gNnyaGo08jditrs';
/** 本專案在 app_data.app 的固定白名單值 */
const APP_ID = 'sharebook';
const SYNC_DEBOUNCE_MS = 2500;

let _supabase = null;
function getSupabase() {
  if (_supabase) return _supabase;
  if (typeof supabase === 'undefined' || !supabase.createClient) {
    console.warn('[分享本本] Supabase SDK 尚未載入');
    return null;
  }
  _supabase = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
      storage: localStorage,
    },
  });
  return _supabase;
}

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

    // ── Supabase Auth / Sync ───────────────────────────────
    authUser: null,
    authEmail: '',
    authPassword: '',
    authConfirmPassword: '',
    authMode: 'login', // 'login' | 'register'
    authError: '',
    authLoading: false,
    showAuthPassword: false,
    syncStatus: 'idle', // idle | pulling | pushing | error | synced
    lastSyncedAt: null,
    cloudUpdatedAt: null,
    _syncTimer: null,
    _skipNextPush: false,
    conflictDialogOpen: false,
    conflictCloudData: null,
    conflictCloudUpdatedAt: null,
    cloudPanelOpen: false,

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

    get isLoggedIn() {
      return !!(this.authUser && this.authUser.id);
    },

    // ── Lifecycle ──────────────────────────────────────────
    async init() {
      this._loadTheme();
      window.addEventListener('online', () => {
        this.isOnline = true;
        if (this.isUnlocked && this.isLoggedIn) this.pullFromCloud({ silent: true });
      });
      window.addEventListener('offline', () => { this.isOnline = false; });
      window.addEventListener('storage', (e) => {
        if (e.key === 'sharebook_lock_signal' && e.newValue && !this.isLocked) {
          this.lock();
        }
      });
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden' && this.isUnlocked) {
          // soft lock optional
        }
      });
      await this._bootstrap();
      await this._initAuth();
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
        this.hasMasterPassword = false;
        this.isFirstSetup = true;
        this.isLocked = true;
        this.isUnlocked = false;
        this.passwords = [];
      }
    },

    async _initAuth() {
      const sb = getSupabase();
      if (!sb) return;
      try {
        const { data: { session } } = await sb.auth.getSession();
        this.authUser = session?.user ?? null;
        if (this.authUser) {
          this.authEmail = this.authUser.email || '';
        }
        sb.auth.onAuthStateChange((event, session) => {
          this.authUser = session?.user ?? null;
          if (this.authUser) {
            this.authEmail = this.authUser.email || '';
            if (this.isUnlocked && event === 'SIGNED_IN') {
              this.pullFromCloud({ silent: false });
            }
          } else {
            this.syncStatus = 'idle';
            this.lastSyncedAt = null;
            this.cloudUpdatedAt = null;
          }
        });
      } catch (e) {
        console.warn('[auth]', e);
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
      const clean = this.passwords.map(({ _noteOpen, ...rest }) => rest);
      const payload = await this._encrypt(clean, this._cryptoKey);
      localStorage.setItem('sharebook_vault', JSON.stringify(payload));
      localStorage.removeItem('passwords');
      this._schedulePush();
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
        await this._saveVault();
        this.hasMasterPassword = true;
        this.isFirstSetup = false;
        this.isLocked = false;
        this.isUnlocked = true;
        this.masterPasswordInput = '';
        this.confirmPasswordInput = '';
        this.showToast('主密碼已設定，資料已加密保護', 'success');
        if (this.isLoggedIn) {
          this.pullFromCloud({ silent: true });
        }
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
        this.passwords = this.passwords.map((p, i) => ({
          ...p,
          id: p.id ?? (Date.now() + i),
          _noteOpen: false,
        }));
        this.isLocked = false;
        this.isUnlocked = true;
        this.masterPasswordInput = '';
        this.showToast('已解鎖', 'success');
        if (this.isLoggedIn) {
          this.pullFromCloud({ silent: false });
        }
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
      this.cancelConflict();
      this.cloudPanelOpen = false;
      this.masterPasswordInput = '';
      this.unlockError = '';
      this._clearSyncTimer();
      try {
        localStorage.setItem('sharebook_lock_signal', String(Date.now()));
      } catch {}
    },

    // ── Supabase Auth ──────────────────────────────────────
    switchAuthMode(mode) {
      this.authMode = mode;
      this.authError = '';
      this.authPassword = '';
      this.authConfirmPassword = '';
    },

    async authSubmit() {
      this.authError = '';
      const email = (this.authEmail || '').trim();
      const password = this.authPassword || '';
      if (!email || !password) {
        this.authError = '請輸入 Email 與密碼';
        return;
      }
      if (this.authMode === 'register') {
        if (password.length < 6) {
          this.authError = '密碼至少 6 個字元';
          return;
        }
        if (password !== this.authConfirmPassword) {
          this.authError = '兩次輸入的密碼不一致';
          return;
        }
      }
      const sb = getSupabase();
      if (!sb) {
        this.authError = '無法連線雲端服務';
        return;
      }
      if (!this.isOnline) {
        this.authError = '目前離線，請連上網路後再試';
        return;
      }
      this.authLoading = true;
      try {
        if (this.authMode === 'register') {
          const { data, error } = await sb.auth.signUp({ email, password });
          if (error) throw error;
          if (data?.user && !data.session) {
            this.showToast('註冊成功，請至信箱確認後再登入', 'success');
            this.authMode = 'login';
            this.authPassword = '';
            this.authConfirmPassword = '';
          } else {
            this.authUser = data?.user ?? null;
            this.showToast('註冊並登入成功', 'success');
            this.authPassword = '';
            this.authConfirmPassword = '';
            this.cloudPanelOpen = false;
            if (this.isUnlocked) await this.pullFromCloud({ silent: false });
          }
        } else {
          const { data, error } = await sb.auth.signInWithPassword({ email, password });
          if (error) throw error;
          this.authUser = data?.user ?? null;
          this.showToast('雲端登入成功', 'success');
          this.authPassword = '';
          this.cloudPanelOpen = false;
          if (this.isUnlocked) await this.pullFromCloud({ silent: false });
        }
      } catch (err) {
        console.error(err);
        const msg = err?.message || String(err);
        if (/invalid login credentials/i.test(msg)) {
          this.authError = 'Email 或密碼錯誤';
        } else if (/already registered|user already/i.test(msg)) {
          this.authError = '此 Email 已註冊，請直接登入';
        } else if (/email not confirmed/i.test(msg)) {
          this.authError = '請先至信箱確認帳號';
        } else {
          this.authError = msg.length > 80 ? '登入失敗，請稍後再試' : msg;
        }
      } finally {
        this.authLoading = false;
      }
    },

    async authLogout() {
      const sb = getSupabase();
      if (!sb) return;
      this.authLoading = true;
      try {
        await sb.auth.signOut();
        this.authUser = null;
        this.syncStatus = 'idle';
        this.lastSyncedAt = null;
        this.cloudUpdatedAt = null;
        this.showToast('已登出雲端帳號', 'success');
      } catch (e) {
        console.error(e);
        this.showToast('登出失敗', 'error');
      } finally {
        this.authLoading = false;
      }
    },

    // ── Cloud Sync ─────────────────────────────────────────
    _clearSyncTimer() {
      if (this._syncTimer) {
        clearTimeout(this._syncTimer);
        this._syncTimer = null;
      }
    },

    _schedulePush() {
      if (!this.isLoggedIn || !this.isUnlocked || !this.isOnline) return;
      if (this._skipNextPush) {
        this._skipNextPush = false;
        return;
      }
      this._clearSyncTimer();
      this._syncTimer = setTimeout(() => {
        this._syncTimer = null;
        this.pushToCloud();
      }, SYNC_DEBOUNCE_MS);
    },

    _buildCloudPayload() {
      const clean = this.passwords.map(({ _noteOpen, ...rest }) => rest);
      return {
        passwords: clean,
        meta: {
          count: clean.length,
          clientUpdatedAt: new Date().toISOString(),
        },
      };
    },

    async pullFromCloud({ silent = false } = {}) {
      if (!this.isLoggedIn || !this.isUnlocked) return;
      const sb = getSupabase();
      if (!sb || !this.isOnline) {
        if (!silent) this.showToast('離線中，無法同步', 'error');
        return;
      }
      this.syncStatus = 'pulling';
      try {
        const { data, error } = await sb
          .from('app_data')
          .select('data, updated_at')
          .eq('owner', this.authUser.id)
          .eq('app', APP_ID)
          .maybeSingle();

        if (error) throw error;

        if (!data) {
          this.syncStatus = 'pushing';
          await this.pushToCloud({ force: true });
          if (!silent) this.showToast('已上傳本機資料到雲端', 'success');
          return;
        }

        this.cloudUpdatedAt = data.updated_at;
        const cloudPayload = data.data;
        const cloudList = Array.isArray(cloudPayload)
          ? cloudPayload
          : (cloudPayload?.passwords || []);

        const localClean = this.passwords.map(({ _noteOpen, ...r }) => r);
        const localStr = JSON.stringify(localClean);
        const cloudStr = JSON.stringify(cloudList);

        if (localStr === cloudStr) {
          this.syncStatus = 'synced';
          this.lastSyncedAt = data.updated_at;
          if (!silent) this.showToast('已與雲端同步', 'success');
          return;
        }

        if (localClean.length === 0 && cloudList.length > 0) {
          this._applyCloudList(cloudList);
          this.syncStatus = 'synced';
          this.lastSyncedAt = data.updated_at;
          if (!silent) this.showToast('已從雲端載入 ' + cloudList.length + ' 筆', 'success');
          return;
        }

        if (cloudList.length === 0 && localClean.length > 0) {
          await this.pushToCloud({ force: true });
          if (!silent) this.showToast('已上傳本機資料到雲端', 'success');
          return;
        }

        this.conflictCloudData = cloudList;
        this.conflictCloudUpdatedAt = data.updated_at;
        this.conflictDialogOpen = true;
        this.syncStatus = 'idle';
      } catch (err) {
        console.error('[pull]', err);
        this.syncStatus = 'error';
        if (!silent) this.showToast('同步失敗：' + (err?.message || '請稍後再試'), 'error');
      }
    },

    async pushToCloud({ force = false } = {}) {
      if (!this.isLoggedIn || !this.isUnlocked) return;
      const sb = getSupabase();
      if (!sb || !this.isOnline) return;
      this.syncStatus = 'pushing';
      try {
        const payload = this._buildCloudPayload();
        const row = {
          owner: this.authUser.id,
          app: APP_ID,
          data: payload,
          updated_at: new Date().toISOString(),
        };
        const { data, error } = await sb
          .from('app_data')
          .upsert(row, { onConflict: 'owner,app' })
          .select('updated_at')
          .single();

        if (error) throw error;
        this.cloudUpdatedAt = data?.updated_at || row.updated_at;
        this.lastSyncedAt = this.cloudUpdatedAt;
        this.syncStatus = 'synced';
      } catch (err) {
        console.error('[push]', err);
        this.syncStatus = 'error';
        this.showToast('上傳失敗：' + (err?.message || '請稍後再試'), 'error');
      }
    },

    _applyCloudList(list) {
      this._skipNextPush = true;
      this.passwords = (list || []).map((p, i) => ({
        ...p,
        id: p.id ?? (Date.now() + i + Math.random()),
        _noteOpen: false,
      }));
      this._saveVault().catch(console.error);
    },

    async resolveConflict(choice) {
      if (choice === 'cloud' && this.conflictCloudData) {
        this._applyCloudList(this.conflictCloudData);
        this.lastSyncedAt = this.conflictCloudUpdatedAt;
        this.cloudUpdatedAt = this.conflictCloudUpdatedAt;
        this.syncStatus = 'synced';
        this.showToast('已採用雲端資料', 'success');
      } else if (choice === 'local') {
        await this.pushToCloud({ force: true });
        this.showToast('已以上傳本機資料覆蓋雲端', 'success');
      }
      this.cancelConflict();
    },

    cancelConflict() {
      this.conflictDialogOpen = false;
      this.conflictCloudData = null;
      this.conflictCloudUpdatedAt = null;
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
      a.download = '分享本本-備份-' + new Date().toISOString().slice(0, 10) + '.json';
      a.click();
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
      const mapped = this.importPreview;
      if (!mapped?.length) {
        this.cancelImport();
        return;
      }
      try {
        if (mode === 'replace') {
          this.passwords = mapped;
          await this._saveVault();
          this.showToast('已取代，共 ' + mapped.length + ' 筆', 'success');
        } else {
          this.passwords = [...mapped, ...this.passwords];
          await this._saveVault();
          this.showToast('已合併匯入 ' + mapped.length + ' 筆', 'success');
        }
      } catch (e) {
        console.error(e);
        this.showToast('匯入失敗：本機儲存空間不足', 'error');
      }
      this.cancelImport();
    },
    exportToHtml() {
      if (!this.isUnlocked) return;
      const rows = this.passwords.map(p =>
        '<tr><td>' + escapeHtml(p.siteName) + '</td><td>' + escapeHtml(p.url) + '</td><td>' +
        escapeHtml(p.username) + '</td><td><code>' + escapeHtml(p.password) + '</code></td><td>' +
        escapeHtml(p.notes) + '</td></tr>'
      ).join('');
      const html = '<!DOCTYPE html><html lang="zh-TW"><head><meta charset="UTF-8"><title>分享本本 匯出</title>' +
        '<style>body{font-family:system-ui;padding:24px;background:#f7f5f0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#0d9488;color:#fff}code{font-family:ui-monospace,monospace}</style></head>' +
        '<body><h1>分享本本 · 匯出 ' + new Date().toLocaleString('zh-TW') + '</h1>' +
        '<table><thead><tr><th>網站</th><th>網址</th><th>帳號</th><th>密碼</th><th>備註</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></body></html>';
      const blob = new Blob([html], { type: 'text/html' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = '分享本本-' + new Date().toISOString().slice(0, 10) + '.html';
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
