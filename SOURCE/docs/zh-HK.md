# SBOX Next 使用指南（香港繁體中文）

SBOX Next 將 VPN 伺服器、管理介面、個人頁面、用量及備份整合在同一個安裝程式內。你仍需自行管理 VPS、網域、供應商防火牆、憑證及私人備份。

**目前為發佈候選版（candidate）。** 以下指令指定一個固定、有校驗碼嘅原始碼版本。安裝、升級、還原、當機復原、Fail2Ban 同真實 VPN 用量計算已喺 Ubuntu 26.10／24.04 systemd 實驗機驗證；最後一步係喺你自己嘅公開伺服器（DNS、ACME、供應商防火牆、真實客戶端）驗收，詳見[候選版狀態](installation.md#package-and-status)同[部署手冊](deployment-runbook.md)。

## 選擇版本及系統

| 項目 | Universal SBOX | ZgoCloud |
| --- | --- | --- |
| 適用對象 | 自行設定伺服器的新部署 | 已持有原有私人解鎖資料及六節點身份的擁有人 |
| Ubuntu 24.04 / 26.04，amd64 | 安裝程式支援 | 安裝程式支援 |
| Ubuntu 26.10 / Debian 12，amd64 | 安裝程式支援 | 安裝程式拒絕 |
| ARM64 或未列出的系統 | 安裝程式拒絕 | 安裝程式拒絕 |
| 原有身份 | 安裝時建立自己的設定 | 保留原有憑證、REALITY 身份、固定連接埠及 UDP 範圍 |

以上是安裝程式的系統限制，並不代表每個系統、網絡及客戶端組合都已完成真實部署驗收。兩個版本均需要 Linux、systemd 及 root 權限。現有安裝只能升級同一產品，不能直接切換 Universal 與 ZgoCloud。

五個伺服器協定系列為 VLESS REALITY + Vision、VMess WebSocket + TLS、Hysteria2、TUIC v5 及 AnyTLS。Hysteria2 可設定 UDP 跳埠；ZgoCloud 亦保留原有 TUIC 別名。客戶端必須支援所選協定及相關 TLS、UDP 設定；同名協定不保證所有軟件都相容。詳見[協定及限制](protocols.md)。

## 安裝前準備

將網域指向 VPS，準備可信任的網域憑證或 ACME 驗證，並在供應商防火牆放行所選 VPN 連接埠及 TCP 9443。HTTP-01 憑證驗證另需 TCP 80。保留供應商控制台及另一條可用的管理連線。

首次安裝可在受支援 VPS 的 root SSH 終端執行：

```bash
cd /root && tar -xzf SING-BOX.tar.gz
cd /root/SING-BOX && bash install.sh
```

請在可信任工作站先核對交付 ZIP 內 `SHA256SUMS` 所列的 `SING-BOX.tar.gz` SHA-256；`install.sh` 會再用 `SING-BOX/SHA256SUMS` 逐個檔案校驗，然後才複製到 VPS。校驗碼可發現損壞，但不是獨立數碼簽章；請與由可信任渠道取得的封存檔摘要比對。

安裝程式已包含應用程式及修改版 sing-box 核心。VPS 不需登入 GitHub、複製產品倉庫或另外下載應用程式。一般系統套件及憑證簽發仍需連接網絡。

### REALITY 握手目標

如啟用 VLESS REALITY，Universal 安裝精靈會問普通 TLS 連線應該到達「遠端網站握手目標」（預設，同以前一樣；SBOX 唔會複製該網站嘅憑證）定係「喺呢部 VPS 上自建嘅 SBOX Personal Cloud 網站」。自建網站只監聽 `127.0.0.1`，並使用你自己網域嘅公開受信任憑證，唔會開放額外公開連接埠，亦唔係管理面板。詳情、切換方法（`sbox reality-fallback`）同疑難排解見 [REALITY 握手目標](reality-fallback.zh-HK.md)。

## 第一次登入及連接裝置

管理介面位於 `https://你的網域:9443`；個人頁面位於同一網址的 `/portal`。在 VPS 本機讀取只有 root 可看的初始管理員資料：

```bash
cat /etc/sbox-webui/bootstrap-admin.txt
```

登入後更改初始密碼、設定雙重認證，並私下保存復原碼。新增用戶，設定數據用量及服務到期日，再建立該用戶的連線資料。個人頁面的帳戶與管理員及 VPN 登入資料分開。

私人連線連結可在日後再次查看；查看不會更換連結。舊有只保存雜湊值的連結仍然有效，但無法重新顯示，必須在通知用戶後明確更換。訂閱連結由客戶端更新，下載的靜態設定檔則需要自行重新匯入。連結及 QR 碼等同私人憑證，只應交給指定用戶。

## 用量、安全及日常操作

```bash
sbox status
sbox doctor
sbox webui doctor
sbox quota show
sbox backup
```

用量來自已認證 VPN 用戶的傳輸統計，與 VPS 網卡流量、協定額外流量及供應商帳單不同。用量上限靠定期收集及執行，可能超出少量或更多；不可當作逐 byte 的計費硬上限。原有共用身份只會顯示合計，不能分辨各位收件人。

圖表所選日期與計劃週期的累積用量可能不同。未收集的歷史不應顯示為零；缺漏、部分記錄及更新延遲應分開理解。請按需要使用表格或 CSV 核對數據。

SSH 防護（`sbox-sshd`）：十分鐘內 SSH 登入失敗六次，來源 IP 會被封十分鐘，並由 nftables 早期規則封鎖該 IP 嘅**所有連接埠**（包括 VPN）。執行設定時嘅 SSH 來源會自動列入白名單，避免鎖住自己。Ubuntu 預設嘅 `[sshd]` jail 只封 22 埠而且次數較少，會同 SBOX 搶先觸發；1.1.1 起，如果該 jail 只由系統套件定義，SBOX 會喺自己嘅設定檔停用佢（你自行改過嘅會保留），移除 SBOX 時自動恢復。舊安裝請執行 `sbox security repair`。`sbox security unban IP` 會由所有持有該 IP 嘅 jail 解封。

Fail2Ban 的 WebUI 防護針對管理介面登入，並不等於所有 VPN 協定都受同一封鎖機制保護。服務已安裝或顯示綠色狀態，不能單獨證明防火牆真的擋住連線。設定安全政策時，保留 SSH 及供應商控制台；查看實際狀態及[安全說明](security.md)。

## 升級、備份及還原

升級前在 VPS 外私下保存完整備份、配對的備份驗證資料、訂閱復原金鑰、憑證來源及之前可用的完整安裝程式與 SHA-256。ZgoCloud 另需原有解鎖資料及六節點身份。先在獲授權的隔離環境驗證還原，再安排維護時段。還原時應使用已核對的本機備份，不要依賴屆時才重新下載。

目前候選版請先在測試環境使用相應升級選項，完成後核對用戶、連線連結、計劃、歷史用量及真實客戶端連線。設定或核心重啟會中斷現有連線。

`sbox recover` 用於處理中斷的交易；`sbox restore /私人路徑/backup.tar.gz` 則會還原歷史資料，並撤銷現有瀏覽器工作階段及 API token。兩者用途不同。不要為了退回介面版本直接覆蓋資料庫，也不要刪除待處理交易檔案來繞過保護。詳見[升級及復原](upgrades-and-recovery.md)。

## 原始碼、支援及私人資料

本交付封存已包含安裝程式、完整產品來源、修改版核心來源、補丁及建置資料，毋須 Git 倉庫或遠端發佈服務。授權及第三方聲明見 [LICENSE](../LICENSE)、[NOTICE](../NOTICE) 及[第三方授權](../THIRD_PARTY_LICENSES/README.md)。安裝前請先在可信任工作站核對交付 ZIP 內 `SHA256SUMS` 所列 `SING-BOX.tar.gz` 嘅 SHA-256，再上傳到 VPS；`install.sh` 會再用 `SING-BOX/SHA256SUMS` 逐個檔案校驗。

真實 IPv6、特定流動網絡、第三方通知送達及特定客戶端仍需在實際環境核實；不保證匿名、繞過封鎖或指定速度。回報問題時提供版本、系統、重現步驟及已遮蓋私人資料的錯誤訊息。不要公開密碼、訂閱連結、QR 碼、用戶資料庫、備份、原有 YAML 或解鎖資料。[英文文件索引](README.md)及[疑難排解](troubleshooting.md)提供進一步說明。
