/**
 * 分享本本 – Secure local password manager
 * AES-GCM + PBKDF2 (600k iterations) · Offline-first
 * + Supabase Email 登入與 app_data 同步
 */
const CRYPTO = {
  PBKDF2_ITERATIONS: 600_000,
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
    pbkdf2Iterations: CRYPTO.PBKDF2_ITERATIONS,
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
      this._autoLockMs = 5 * 60 * 1000; // 背景 5 分鐘後自動鎖定
      this._hiddenAt = null;
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden' && this.isUnlocked) {
          // 背景時立刻 flush 待發 push（不阻塞）
          if (this._syncTimer && this._cryptoKey && this.isLoggedIn && this.isOnline) {
            this._clearSyncTimer();
            this.pushToCloud({ force: true }).catch(() => {});
          }
          this._hiddenAt = Date.now();
        } else if (document.visibilityState === 'visible') {
          // 用時間戳判斷，避免背景 setTimeout 被節流而永遠不鎖
          if (this._hiddenAt && this.isUnlocked &&
              (Date.now() - this._hiddenAt) >= this._autoLockMs) {
            this.lock();
            this.showToast('已因閒置自動鎖定', 'info');
          }
          this._hiddenAt = null;
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
        // 已有加密庫：立刻清除殘留明文，避免中間視窗
        if (plain) {
          try { localStorage.removeItem('passwords'); } catch {}
        }
      } else if (plain) {
        this.hasMasterPassword = false;
        this.isFirstSetup = true;
        this.isLocked = true;
        this.isUnlocked = false;
        try {
          const parsed = JSON.parse(plain);
          this.passwords = Array.isArray(parsed) ? parsed : [];
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
              // 延遲到 auth 鎖外，避免 supabase-js 回調內 await 查詢死鎖
              setTimeout(() => this.pullFromCloud({ silent: false }), 0);
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
    async _deriveKey(password, salt, iterations = CRYPTO.PBKDF2_ITERATIONS) {
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
      );
      return crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations,
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
    async _saveVault({ skipPush = false } = {}) {
      if (!this._cryptoKey) return;
      const clean = this.passwords.map(({ _noteOpen, _pwdVisible, ...rest }) => rest);
      const payload = await this._encrypt(clean, this._cryptoKey);
      localStorage.setItem('sharebook_vault', JSON.stringify(payload));
      localStorage.removeItem('passwords');
      // skipPush：僅寫本地（例如 adopt KDF 尚未決定衝突結果前），避免提前覆蓋雲端
      if (!skipPush) this._schedulePush();
    },
    async _loadVault() {
      const raw = localStorage.getItem('sharebook_vault');
      if (!raw || !this._cryptoKey) return [];
      const payload = JSON.parse(raw);
      const data = await this._decrypt(payload, this._cryptoKey);
      return Array.isArray(data) ? data : [];
    },

    // ── Unlock / Setup ─────────────────────────────────────
    async setupMasterPassword() {
      this.unlockError = '';
      // 不 trim：前後空格視為密碼的一部分（與 unlock 一致）
      const pw = this.masterPasswordInput;
      const confirm = this.confirmPasswordInput;
      if (!pw || pw.length < 8) {
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
        this._cryptoKey = await this._deriveKey(pw, salt, CRYPTO.PBKDF2_ITERATIONS);
        this.pbkdf2Iterations = CRYPTO.PBKDF2_ITERATIONS;
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
          this.pullFromCloud({ silent: true, password: pw });
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
        const storedIters = (typeof meta.iterations === 'number' && meta.iterations > 0)
          ? meta.iterations
          : CRYPTO.PBKDF2_ITERATIONS;
        this.pbkdf2Iterations = storedIters;
        this._cryptoKey = await this._deriveKey(pw, salt, storedIters);
        this.passwords = await this._loadVault();
        this.passwords = this.passwords.map((p, i) => ({
          ...p,
          id: p.id ?? (Date.now() + i),
          _noteOpen: false,
          _pwdVisible: false,
        }));
        // 迭代升級：meta 記錄的 iterations 低於目前常數 → 用新迭代重派生並重寫 vault
        if (storedIters < CRYPTO.PBKDF2_ITERATIONS) {
          try {
            this._cryptoKey = await this._deriveKey(pw, salt, CRYPTO.PBKDF2_ITERATIONS);
            this.pbkdf2Iterations = CRYPTO.PBKDF2_ITERATIONS;
            this._writeMeta({
              ...meta,
              iterations: CRYPTO.PBKDF2_ITERATIONS,
              upgradedAt: Date.now(),
            });
            await this._saveVault();
          } catch (upErr) {
            console.warn('[iterations upgrade]', upErr);
          }
        }
        this.isLocked = false;
        this.isUnlocked = true;
        this.masterPasswordInput = '';
        this.showToast('已解鎖', 'success');
        if (this.isLoggedIn) {
          // 僅在此瞬間把密碼傳入 pull，用於跨裝置 salt 對齊；不駐留狀態
          this.pullFromCloud({ silent: false, password: pw });
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
      // snapshot：保留不可導出的 CryptoKey + 清單 + salt，立刻清空 UI 狀態
      const shouldFlush = !!(this._syncTimer && this._cryptoKey && this.isLoggedIn && this.isOnline);
      this._clearSyncTimer();
      let flushSnap = null;
      if (shouldFlush) {
        try {
          const saltB64 = this._salt
            ? this._bufToB64(this._salt)
            : (this._readMeta()?.salt || null);
          flushSnap = {
            owner: this.authUser?.id,
            key: this._cryptoKey, // extractable:false，XSS 也無法匯出原始位元組
            passwords: this.passwords.map(({ _noteOpen, _pwdVisible, ...rest }) => rest),
            saltB64,
            iterations: this.pbkdf2Iterations || CRYPTO.PBKDF2_ITERATIONS,
          };
        } catch (e) {
          console.warn('[lock snapshot]', e);
          flushSnap = null;
        }
      }

      // 核心鎖定：同步立即執行（不等待網路）
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
      this._hiddenAt = null;
      try {
        localStorage.setItem('sharebook_lock_signal', String(Date.now()));
      } catch {}

      if (flushSnap) {
        this._flushWithKey(flushSnap).catch((e) => console.warn('[flush on lock]', e));
      }
    },

    /** 用鎖定前 snapshot 的 CryptoKey 加密上傳（不經主密碼字串） */
    async _flushWithKey(snap) {
      if (!snap?.owner || !snap.key || !snap.saltB64) return;
      const sb = getSupabase();
      if (!sb || !navigator.onLine) return;
      try {
        const plain = {
          passwords: snap.passwords || [],
          meta: { count: (snap.passwords || []).length, clientUpdatedAt: new Date().toISOString() },
        };
        const sealed = await this._encrypt(plain, snap.key);
        const payload = {
          v: 3,
          enc: true,
          salt: snap.saltB64,
          iterations: snap.iterations,
          iv: sealed.iv,
          data: sealed.data,
        };
        await sb.from('app_data').upsert({
          owner: snap.owner,
          app: APP_ID,
          data: payload,
          updated_at: new Date().toISOString(),
        }, { onConflict: 'owner,app' });
      } finally {
        snap.key = null;
        snap.passwords = null;
      }
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
    _clearAutoLockTimer() {
      this._hiddenAt = null;
      if (this._autoLockTimer) {
        clearTimeout(this._autoLockTimer);
        this._autoLockTimer = null;
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

    /**
     * 雲端 payload：用已解鎖的 _cryptoKey（extractable:false）加密。
     * 封包附帶本機 salt + iterations，供他機在「解鎖當下」用主密碼對齊 salt。
     * 結構：{ v:3, enc:true, salt, iterations, iv, data }
     * 不在狀態中保存主密碼明文。
     */
    async _buildCloudPayloadEncrypted() {
      if (!this._cryptoKey) throw new Error('尚未解鎖，無法加密上傳');
      let saltB64;
      let iterations = this.pbkdf2Iterations || CRYPTO.PBKDF2_ITERATIONS;
      if (this._salt) {
        saltB64 = this._bufToB64(this._salt);
      } else {
        const meta = this._readMeta();
        saltB64 = meta?.salt;
        if (typeof meta?.iterations === 'number') iterations = meta.iterations;
      }
      if (!saltB64) throw new Error('缺少 salt，無法上傳');

      const clean = this.passwords.map(({ _noteOpen, _pwdVisible, ...rest }) => rest);
      const plain = {
        passwords: clean,
        meta: {
          count: clean.length,
          clientUpdatedAt: new Date().toISOString(),
        },
      };
      const sealed = await this._encrypt(plain, this._cryptoKey);
      return {
        v: 3,
        enc: true,
        salt: saltB64,
        iterations,
        iv: sealed.iv,
        data: sealed.data,
      };
    },

    /**
     * 解密雲端 data。
     * - 同 salt → 直接用 _cryptoKey
     * - 不同 salt 且提供了 password（僅 unlock 當下）→ 臨時派生、用完不保存
     * - 不同 salt 且無 password → 拋錯提示重新解鎖以對齊
     */
    async _decodeCloudData(cloudPayload, password = null) {
      if (!cloudPayload) return { list: [], adopted: false };

      if (cloudPayload && cloudPayload.enc === true && cloudPayload.iv && cloudPayload.data) {
        try {
          const localSaltB64 = this._salt
            ? this._bufToB64(this._salt)
            : (this._readMeta()?.salt || null);
          const cloudSalt = cloudPayload.salt || null;
          const cloudIters = (typeof cloudPayload.iterations === 'number' && cloudPayload.iterations > 0)
            ? cloudPayload.iterations
            : CRYPTO.PBKDF2_ITERATIONS;

          let key = null;
          let needAdopt = false;

          if (!cloudSalt) {
            // 舊 v2：無 salt，只能同裝置
            if (!this._cryptoKey) throw new Error('尚未解鎖，無法解密雲端資料');
            key = this._cryptoKey;
          } else if (localSaltB64 && cloudSalt === localSaltB64) {
            if (!this._cryptoKey) throw new Error('尚未解鎖，無法解密雲端資料');
            key = this._cryptoKey;
          } else if (password) {
            // 跨裝置：用解鎖當下的密碼臨時派生（不寫入 this）
            key = await this._deriveKey(password, this._b64ToBuf(cloudSalt), cloudIters);
            needAdopt = true;
          } else {
            throw new Error('雲端金鑰參數與本機不同，請鎖定後重新解鎖以同步');
          }

          const plain = await this._decrypt(
            { iv: cloudPayload.iv, data: cloudPayload.data },
            key
          );
          let list = [];
          if (Array.isArray(plain)) list = plain;
          else if (plain && Array.isArray(plain.passwords)) list = plain.passwords;

          // 若需對齊 salt：把雲端 salt 寫入本機 meta，並用 password 重派生 _cryptoKey
          if (needAdopt && password && cloudSalt) {
            await this._adoptCloudKdf(password, cloudSalt, cloudIters);
          }

          return { list, adopted: needAdopt };
        } catch (e) {
          console.error('[cloud decrypt]', e);
          const msg = (e && e.message) ? String(e.message) : '';
          if (/尚未解鎖|重新解鎖|金鑰參數/.test(msg)) throw e;
          throw new Error('雲端資料解密失敗（請確認主密碼相同）');
        }
      }

      // 舊版明文相容
      if (Array.isArray(cloudPayload)) return { list: cloudPayload, adopted: false };
      if (cloudPayload && Array.isArray(cloudPayload.passwords)) {
        return { list: cloudPayload.passwords, adopted: false };
      }
      return { list: [], adopted: false };
    },

    /** 採用雲端 salt/iterations 為本機 KDF 參數，並重寫本地 vault */
    async _adoptCloudKdf(password, cloudSaltB64, cloudIters) {
      const saltBuf = this._b64ToBuf(cloudSaltB64);
      const newKey = await this._deriveKey(password, saltBuf, cloudIters);
      this._salt = saltBuf;
      this._cryptoKey = newKey;
      this.pbkdf2Iterations = cloudIters;
      const prevMeta = this._readMeta() || {};
      this._writeMeta({
        ...prevMeta,
        version: prevMeta.version || 1,
        salt: cloudSaltB64,
        iterations: cloudIters,
        adoptedFromCloudAt: Date.now(),
      });
      await this._saveVault({ skipPush: true });
    },

    async pullFromCloud({ silent = false, password = null } = {}) {
      if (!this.isLoggedIn || !this.isUnlocked || !this._cryptoKey) return;
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
          if (!silent) this.showToast('已上傳本機資料到雲端（已加密）', 'success');
          return;
        }

        this.cloudUpdatedAt = data.updated_at;
        let cloudList = [];
        let adopted = false;
        try {
          const decoded = await this._decodeCloudData(data.data, password);
          cloudList = decoded.list || [];
          adopted = !!decoded.adopted;
        } catch (decErr) {
          this.syncStatus = 'error';
          if (!silent) this.showToast(decErr.message || '雲端解密失敗', 'error');
          return;
        }

        const raw = data.data;
        const isLegacyPlain = raw && raw.enc !== true && (
          Array.isArray(raw) || (raw && Array.isArray(raw.passwords))
        );
        const needsEnvelopeUpgrade = raw && raw.enc === true && !raw.salt;
        const shouldUpgrade = isLegacyPlain || needsEnvelopeUpgrade || adopted;

        const localClean = this.passwords.map(({ _noteOpen, _pwdVisible, ...r }) => r);
        const localStr = JSON.stringify(localClean);
        const cloudStr = JSON.stringify(cloudList);

        if (localStr === cloudStr) {
          this.syncStatus = 'synced';
          this.lastSyncedAt = data.updated_at;
          if (shouldUpgrade) await this.pushToCloud({ force: true });
          if (!silent) this.showToast('已與雲端同步', 'success');
          return;
        }

        if (localClean.length === 0 && cloudList.length > 0) {
          this._applyCloudList(cloudList);
          this.syncStatus = 'synced';
          this.lastSyncedAt = data.updated_at;
          if (shouldUpgrade) await this.pushToCloud({ force: true });
          if (!silent) this.showToast('已從雲端載入 ' + cloudList.length + ' 筆', 'success');
          return;
        }

        if (cloudList.length === 0 && localClean.length > 0) {
          await this.pushToCloud({ force: true });
          if (!silent) this.showToast('已上傳本機資料到雲端（已加密）', 'success');
          return;
        }

        // 兩邊都有且不同：衝突（salt 已在 decode 時對齊，若有 password）
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
      if (!this.isLoggedIn || !this.isUnlocked || !this._cryptoKey) return;
      const sb = getSupabase();
      if (!sb || !this.isOnline) return;
      this.syncStatus = 'pushing';
      try {
        const payload = await this._buildCloudPayloadEncrypted();
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
        _pwdVisible: false,
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
            _pwdVisible: false,
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
      const MAX_BYTES = 5 * 1024 * 1024; // 5MB
      if (file.size > MAX_BYTES) {
        this.showToast('檔案過大（上限 5MB）', 'error');
        event.target.value = '';
        return;
      }
      try {
        const text = await file.text();
        if (text.length > MAX_BYTES) {
          this.showToast('檔案過大（上限 5MB）', 'error');
          event.target.value = '';
          return;
        }
        const data = JSON.parse(text);
        if (!Array.isArray(data)) throw new Error('格式錯誤：需為陣列');
        if (data.length > 10000) {
          this.showToast('項目過多（上限 10000 筆）', 'error');
          event.target.value = '';
          return;
        }
        const mapped = data.map((p, i) => {
          if (!p || typeof p !== 'object') return null;
          // 欄位白名單：只取已知鍵
          const siteName = String(p.siteName || p.site || '').slice(0, 500);
          const username = String(p.username || p.user || '').slice(0, 500);
          const password = String(p.password || '').slice(0, 2000);
          const url = String(p.url || '').slice(0, 2000);
          const notes = String(p.notes || '').slice(0, 5000);
          if (!siteName || !username) return null;
          return {
            id: (typeof p.id === 'number' || typeof p.id === 'string') ? p.id : (Date.now() + i + Math.random()),
            siteName,
            url,
            username,
            password,
            notes,
            createdAt: typeof p.createdAt === 'number' ? p.createdAt : undefined,
            _noteOpen: false,
            _pwdVisible: false,
          };
        }).filter(Boolean);
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
