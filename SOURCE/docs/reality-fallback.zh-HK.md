# REALITY 握手目標：遠端網站或自建 Personal Cloud 網站

[English](reality-fallback.md)

VLESS REALITY 用自己嘅 REALITY 金鑰對同 short ID 驗證客戶端。其他所有到達 REALITY 連接埠嘅 TLS 連線——例如普通瀏覽器、掃描器或探測——都會被轉送去一個**握手目標**。Universal SBOX 提供兩種目標；ZgoCloud 會保留受保護嘅原有設定，唔提供呢個選項。

| | 遠端網站握手目標（預設） | 自建 SBOX Personal Cloud 網站 |
| --- | --- | --- |
| 普通訪客會到達 | 你揀選嘅知名遠端網站（`www.cloudflare.com`、`www.microsoft.com`、`www.apple.com` 或自訂主機名稱） | 喺呢部 VPS 上運行、只讀嘅小型 Personal Cloud 網站 |
| 訪客見到嘅憑證 | 嗰個網站自己嘅憑證，由嗰個網站提供 | **你自己**網域嘅受信任憑證 |
| 客戶端 SNI | 遠端主機名稱 | 你嘅 SBOX 網域 |
| 額外要求 | 冇 | 網域 DNS 指向呢部 VPS，並有公開受信任憑證（Let's Encrypt DNS-01／HTTP-01 或你自己嘅憑證同私鑰） |
| 額外公開連接埠 | 冇 | 冇——網站只監聽 `127.0.0.1` |

**兩種模式都唔會複製、下載或「盜用」任何憑證。** 遠端模式只係將遠端主機設為轉送目的地；SBOX 從來唔會取得、複製或儲存該網站嘅憑證或私鑰。SBOX 其他地方嘅憑證 `reuse`（重用）選項，意思係重用**呢個安裝自己**仍然有效嘅憑證。REALITY 金鑰對係 REALITY 專用憑據，唔係網站憑證。

## 安裝時選擇

只有喺 Universal 安裝精靈啟用 VLESS REALITY 時先會問：

```text
REALITY handshake target (what an ordinary browser or probe sees on the REALITY port):
  1) Remote website handshake target (default, current behaviour)
  2) Self-hosted SBOX Personal Cloud website on this VPS
```

揀 2 之後會問本機網站連接埠（預設 `8443`，只限 loopback，1024–65535，唔可以係 `9443`，亦唔可以同已啟用 VPN 協定或其他程式重複）。網站主機名稱固定係已設定嘅 SBOX 網域，REALITY 亦會用呢個網域做 SNI。

之後嘅憑證步驟一定要用公開受信任、涵蓋該網域嘅憑證：Cloudflare DNS-01、HTTP-01、你自己嘅憑證／私鑰路徑，或重用呢個安裝自己嘅受信任憑證。呢個模式唔提供自簽憑證。如果未能提供受信任憑證，可以揀 **0 — 返回**，安裝程式會改返用遠端網站握手目標，其他設定不變。簽發失敗會令交易停止並還原，唔會靜靜雞降級。

無人值守安裝要明確指定：

```bash
sbox install global --yes --domain cloud.example.com --protocols reality \
  --reality-fallback self-hosted --reality-fallback-port 8443 \
  --cert certbot-dns-cloudflare --cf-token-file /root/cf.token --email none
```

如果冇 `--reality-fallback`，無人值守執行會保留現有模式（所有現有安裝都係遠端模式）。

## 之後切換

```bash
sbox reality-fallback status
sbox reality-fallback check                 # 驗證本機 HTTPS 同 REALITY 轉送
sbox reality-fallback self-hosted [--port 8443] [--cert ...]
sbox reality-fallback remote [--sni www.cloudflare.com]
```

`sbox configure` 亦會以互動方式提供同一個選擇。切換返遠端模式時，會還原自建模式之前用緊嘅遠端主機名稱（或你用 `--sni` 指定嘅名稱）。每次切換都係一個交易：狀態、伺服器設定、客戶端匯出、網站服務同憑證會一齊套用，失敗就一齊還原。**切換後客戶端 SNI 會改變，請重新匯入客戶端設定檔。** REALITY 金鑰、short ID、UUID 同連接埠都唔會改變。

## VPS 上會運行乜嘢

- `sbox-fallback-web.service`——由 SBOX 擁有嘅 systemd 服務（標示 `Managed by sbox-manager`），喺 `sing-box.service` 之前啟動，只喺自建模式啟用。
- 伺服器係 Python 標準函式庫寫成嘅 `server.py` 靜態 HTTPS 伺服器，連同網站隨管理程式安裝喺 `/usr/local/lib/sbox-manager/fallback-web/`。唔會安裝 Nginx、Caddy 或 Apache，亦唔會改動現有網頁伺服器設定。
- 服務以臨時、無特權用戶運行（`DynamicUser=yes`），冇任何 capability，只以唯讀方式掛載網站目錄，並設有 `ProtectSystem=strict`、私人 `/tmp` 同裝置、系統呼叫過濾、除 localhost 外 `IPAddressDeny=any`、`SocketBindAllow=tcp:連接埠`、`MemoryMax=96M`、`TasksMax=256` 同 `CPUQuota=50%`。佢無法存取 SBOX 狀態、備份、用量資料、WebUI 同 Let's Encrypt 目錄。
- 憑證同私鑰經 systemd `LoadCredential=` 由 SBOX 管理嘅現行憑證提供；私鑰唔會變成人人可讀，亦唔會複製到網站目錄。
- 監聽地址只接受 `127.0.0.1` 或 `::1`，其他地址會喺啟動時被拒絕。唔會新增防火牆規則。

### 網站內容

原創 **SBOX Personal Cloud** 網站有四頁——**主頁（Home）**、**檔案（Files）**、**媒體（Media）** 同 **關於（About）**——另有 404 頁。檔案頁列出一個精選、只讀嘅細型資料庫（文件、試算表、圖片），附大小、日期同下載按鈕；媒體頁係原創插圖相簿。全部資源都喺本機並且係原創，冇外部字型、程式碼、圖片、分析工具或第三方品牌。網站內容目前以英文提供。

安全特性：只接受 `GET`／`HEAD`（其他方法回覆 405）、拒絕請求內容、冇目錄清單、冇隱藏檔、冇符號連結、冇路徑穿越、冇可執行內容，並設有嚴格 Content-Security-Policy、`nosniff`、`no-referrer`、`frame-ancestors 'none'`，以及請求行、標頭、時間同同時連線數上限。`Host` 唔啱會回覆 421。呢個網站唔係 SBOX 管理面板，唔會顯示 SBOX 狀態、憑據、連接埠或診斷資料。

網站屬於產品內容，升級時會被取代；呢個功能唔包括自訂網站內容。

## 憑證續期同健康檢查

續期沿用現有交易式部署掛鈎。部署新憑證時，SBOX 會重新啟動網站（令 systemd 重新讀取憑證）、驗證網站、重新啟動 sing-box，再驗證 REALITY 會將普通 HTTPS 請求轉送到網站。任何失敗都會還原交易並記錄；`sbox doctor` 會顯示警告，連同時間同原因。

自建模式下 `sbox doctor` 會報告：握手目標、網站主機名稱同 loopback 監聽；網站檔案已安裝及服務設定同狀態一致；服務運行中及已設定開機啟動；只監聽 loopback、憑證受系統信任並涵蓋主機名稱、所有頁面都能提供；REALITY 會將 REALITY 連接埠上嘅普通 HTTPS 轉送到網站；網站連接埠冇公開防火牆規則；以及最近一次啟用失敗（如有）。遠端模式會報告遠端目標，並確認冇殘留網站服務。

## 備份、升級同移除

模式記錄喺狀態入面，所以備份、還原同升級都會保留。舊狀態冇 `fallback` 物件，會當作遠端模式處理，SNI、目的地同客戶端設定檔逐位元組相同。移除 SBOX 時會停止並刪除由 SBOX 擁有嘅服務。Let's Encrypt 憑證同以前一樣會保留。

## 資源用量

離線量度（Python 3.13，處理 50 個 HTTPS 頁面請求後）伺服器約用 26 MB 常駐記憶體；網站連範例資料約 45 KB。CPU 同記憶體受上面服務限制約束；實際數字視乎 Python 版本。

## 疑難排解

| 情況 | 檢查 |
| --- | --- |
| 安裝程式拒絕憑證 | 憑證必須公開受信任、未過期並涵蓋 SBOX 網域。自簽或測試憑證會被拒絕。 |
| `sbox doctor`：網站服務未運行 | `journalctl -u sbox-fallback-web -n 50`；`refused:` 或 `preflight:` 開頭嘅一行會講明係監聽、憑證定邊個檔案出問題。 |
| 安裝後出現 `site root has no index.html`／冇 listener（Ubuntu 26.10 用 1.1.0） | 1.1.1 已修正。Ubuntu 26.10 預設用 Rust 版 uutils `mv`；舊安裝程式由 `/run` 搬網站去磁碟時，會用管理程式嘅 `077` umask 重建目錄，令 `site/` 變成 `0700`，無特權嘅服務讀唔到。交易隨即還原，所以之後見唔到目錄同服務檔。請用 1.1.1 安裝程式。 |
| 「REALITY relays ordinary HTTPS」失敗 | 確認 `sing-box.service` 運行中，並用 `sbox reality-fallback status` 確認 REALITY 以 SBOX 網域做 SNI。 |
| 連接埠衝突 | 用 `sbox reality-fallback self-hosted --port N` 改用另一個 loopback 連接埠。 |
| 想用返以前嘅做法 | `sbox reality-fallback remote`，然後重新匯入客戶端設定檔。 |

## 驗證狀態

離線測試同隔離網絡命名空間實驗室已驗證狀態渲染、安裝程式函式、網站、服務強化設定、續期重新啟動、還原掛鈎，以及兩種 REALITY 模式配合固定版本核心（見 [testing](testing.md)）。1.1.1 另外喺用 Ubuntu 26.10（systemd 261、Python 3.14、uutils coreutils）同 Ubuntu 24.04 套件庫建立嘅可棄置 systemd 實驗機上完整安裝：全新安裝、配對升級、注入故障後還原、中途當機復原、移除同重裝，並用真實 VPN 流量及經 REALITY 埠嘅外部 HTTPS 驗證。公開 DNS、公開憑證簽發同真實 VPS 仍屬部署檢查；請喺可棄置伺服器執行 `tools/vps_acceptance.sh`。

- **先完成握手、後限制連線。** REALITY 會將連接埠上每個 ClientHello（包括已認證用戶）轉交本網站，並需要本網站完成 TLS 握手先可以完成已認證連線。最多接受 192 個同時進行嘅 TLS 握手（握手逾時 5 秒）；32 個連線上限只限制 TLS 之後嘅網頁服務，超出嘅訪客會喺已完成嘅 TLS 連線收到細小嘅 `503 Service Unavailable`。只有超出握手上限嘅連線先會喺 TLS 之前關閉。1.2.0 之前，約 32 個同時嘅未認證訪客已足以令已認證 REALITY 連線失敗（實測：64 個並行訪客下 120 個請求有 26 個失敗）。
