# 分享本本 · 加密密碼管理 PWA

安全、離線優先的密碼與資料管理工具。所有資料以 **AES-256-GCM** 加密後僅存在本機瀏覽器，金鑰由主密碼經 **PBKDF2（120,000 次迭代）** 衍生，關閉分頁或重新整理後必須再次解鎖。

## 安全機制

| 項目 | 說明 |
|------|------|
| 加密 | AES-GCM 256-bit |
| 金鑰衍生 | PBKDF2-SHA256 · 120,000 次迭代 |
| 鹽值 | 每保險庫獨立隨機 16 bytes |
| IV | 每次寫入隨機 12 bytes |
| 記憶體 | 金鑰僅存在 RAM，鎖定則清除 |
| 遷移 | 偵測到舊版明文 `passwords` 時，首次設定主密碼會自動加密並移除明文 |

## UI 特色

- Glassmorphism 毛玻璃效果
- 完整 Dark Mode（跟隨系統 + 手動切換）
- 藥丸形（pill）按鈕與搜尋框，尺寸統一
- Safe-area / notch / Dynamic Island 支援
- 滑入式 Modal 動畫
- Toast 訊息
- 鎖定按鈕一鍵上鎖

## 使用方式

1. 用瀏覽器開啟 `index.html`（建議本機 HTTP server 或直接 file 亦可）
2. 首次使用會要求設定主密碼（至少 8 字元）
3. 若本機已有舊版未加密資料，會自動遷移加密
4. 關閉分頁或重新整理後需重新輸入主密碼解鎖

> **重要**：主密碼無法復原。遺失主密碼 = 資料永久無法解密。

## 檔案結構

```
share-notebook/
├── index.html      # 主介面
├── app.js          # Alpine 狀態 + Web Crypto 邏輯
├── manifest.json   # PWA manifest
└── icons/          # 圖示（可自行替換）
```

## 技術

- Alpine.js 3
- Web Crypto API（原生，無需額外套件）
- 純 CSS 變數 + 毛玻璃，無 Tailwind 建置依賴
- Phosphor Icons（CDN）

## 匯出 / 匯入

解鎖後可匯出 JSON 備份或 HTML 清單。匯入 JSON 會合併到現有資料並重新加密寫入。
