# Proxy Farm — cài đặt và chạy trên Windows (Docker Desktop + WSL2).
# Cách dùng: nháy đúp start-windows.bat (file này được gọi từ đó), hoặc trong PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\run.ps1 [-LowResource 1|0] [-MaxActive 3] [-Port 8090] [-NoBrowser]
# Việc nó làm: kiểm tra ảo hoá + WSL2 + Docker Desktop (chỉ dẫn bằng tiếng Việt nếu thiếu),
# ghi .env, build hai image, chạy manager rồi mở http://127.0.0.1:8090.
# Lưu ý: file này phải giữ mã hoá UTF-8 có BOM để PowerShell 5.1 đọc đúng tiếng Việt.
param(
  [string]$LowResource = "",
  [string]$MaxActive = "",
  [int]$Port = 0,
  [switch]$NoBrowser
)
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
Set-Location -LiteralPath $PSScriptRoot

function Say([string]$m)  { Write-Host $m }
function Ok([string]$m)   { Write-Host ("  [OK] " + $m) -ForegroundColor Green }
function Warn([string]$m) { Write-Host ("  [!]  " + $m) -ForegroundColor Yellow }
function Fail([string]$title, [string[]]$steps) {
  Write-Host ""
  Write-Host ("[X] " + $title) -ForegroundColor Red
  $i = 1
  foreach ($s in $steps) { Write-Host ("    " + $i + ". " + $s); $i++ }
  Write-Host ""
  Write-Host "Làm xong các bước trên thì nháy đúp lại start-windows.bat." -ForegroundColor Cyan
  exit 1
}

Say ""
Say "=== Proxy Farm — kiểm tra máy ==="

# ---- 1. RAM -------------------------------------------------------------------------
$ramGB = 0
try { $ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1) } catch {}
if ($ramGB -gt 0) {
  if ($ramGB -lt 4)      { Warn "Máy có $ramGB GB RAM — rất ít. Docker Desktop cần tối thiểu khoảng 4 GB; chỉ nên bật 1–2 proxy." }
  elseif ($ramGB -lt 8)  { Ok "RAM: $ramGB GB — sẽ bật chế độ máy yếu (tối đa 3 proxy cùng lúc)." }
  else                   { Ok "RAM: $ramGB GB" }
}

# ---- 2. Ảo hoá (VT-x / AMD-V) --------------------------------------------------------
$hv = $false; $vt = $null
try {
  $hv = [bool](Get-CimInstance Win32_ComputerSystem).HypervisorPresent
  $vt = (Get-CimInstance Win32_Processor | Select-Object -First 1).VirtualizationFirmwareEnabled
} catch {}
if ($hv) { Ok "Ảo hoá: đang bật" }
elseif ($vt -eq $true) { Ok "Ảo hoá: đã bật trong BIOS" }
elseif ($vt -eq $false) {
  Fail "Chưa bật ảo hoá (Virtualization) trong BIOS/UEFI — Docker cần nó." @(
    "Khởi động lại máy, bấm phím vào BIOS ngay khi vừa bật (thường là F2, F10, Del hoặc Esc tuỳ hãng).",
    "Tìm mục 'Intel Virtualization Technology' / 'VT-x' / 'SVM Mode' / 'AMD-V' và chọn Enabled.",
    "Lưu lại (thường là F10) rồi khởi động lại.",
    "Kiểm tra: mở Task Manager > Performance > CPU, dòng 'Virtualization: Enabled'.")
}
else { Warn "Không đọc được trạng thái ảo hoá — bỏ qua bước này." }

# ---- 3. WSL2 ------------------------------------------------------------------------
$wslOk = $false
if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
  & wsl.exe --status *> $null
  if ($LASTEXITCODE -eq 0) { $wslOk = $true }
}
if ($wslOk) { Ok "WSL2: đã cài" }
else {
  Fail "Chưa cài WSL2 (Windows Subsystem for Linux) — Docker Desktop chạy trên nó." @(
    "Bấm Start, gõ PowerShell, chuột phải chọn 'Run as administrator' (Chạy với quyền quản trị).",
    "Gõ lệnh:  wsl --install  rồi Enter, đợi chạy xong.",
    "Khởi động lại máy.",
    "Windows 10 cần bản 21H2 trở lên (Settings > Windows Update để cập nhật).")
}

# ---- 4. Docker Desktop --------------------------------------------------------------
$dockerExe = Get-Command docker -ErrorAction SilentlyContinue
$desktop = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
if (-not $dockerExe -and -not (Test-Path $desktop)) {
  Fail "Chưa cài Docker Desktop." @(
    "Tải Docker Desktop cho Windows: https://www.docker.com/products/docker-desktop/  (hoặc trong PowerShell: winget install -e --id Docker.DockerDesktop)",
    "Cài với lựa chọn mặc định — giữ dấu tích 'Use WSL 2 instead of Hyper-V'.",
    "Mở Docker Desktop một lần, chấp nhận điều khoản, đợi tới khi góc dưới trái báo 'Engine running'.",
    "Máy yếu: trong Docker Desktop > Settings > General, bỏ tích 'Start Docker Desktop when you sign in' nếu không muốn nó chạy mỗi lần bật máy.")
}
if (-not $dockerExe) { $env:Path += ";" + (Join-Path $env:ProgramFiles "Docker\Docker\resources\bin") }

function DockerUp { & docker info *> $null; return ($LASTEXITCODE -eq 0) }
if (-not (DockerUp)) {
  if (Test-Path $desktop) {
    Say "  ...  Đang mở Docker Desktop (lần đầu có thể mất 1–3 phút)"
    Start-Process -FilePath $desktop | Out-Null
  }
  $t = 0
  while (-not (DockerUp) -and $t -lt 240) { Start-Sleep -Seconds 5; $t += 5; Write-Host -NoNewline "." }
  Write-Host ""
  if (-not (DockerUp)) {
    Fail "Docker Desktop chưa chạy được." @(
      "Mở Docker Desktop từ menu Start, đợi tới khi báo 'Engine running'.",
      "Nếu nó báo lỗi WSL: mở PowerShell (Run as administrator) và chạy  wsl --update  rồi khởi động lại máy.",
      "Nếu báo thiếu bộ nhớ: xem mục 'Cài trên Windows từng bước' trong README (file .wslconfig).")
  }
}
Ok "Docker Desktop: đang chạy"
$os = (& docker info --format "{{.OSType}}" 2>$null)
if ($os -ne "linux") {
  Fail "Docker đang ở chế độ Windows containers." @(
    "Chuột phải biểu tượng Docker (cá voi) ở khay hệ thống, chọn 'Switch to Linux containers...'.")
}
& docker compose version *> $null
if ($LASTEXITCODE -ne 0) {
  Fail "Docker Desktop quá cũ (thiếu 'docker compose')." @("Cập nhật Docker Desktop lên bản mới nhất.")
}

# ---- 5. .wslconfig cho máy yếu -------------------------------------------------------
$wslcfg = Join-Path $env:USERPROFILE ".wslconfig"
if ($ramGB -gt 0 -and $ramGB -lt 8 -and -not (Test-Path $wslcfg)) {
  $mem = if ($ramGB -lt 6) { "2GB" } else { "3GB" }
  Warn "Máy ít RAM: nên giới hạn RAM cho WSL2/Docker để Windows không bị đơ."
  $ans = Read-Host "  Tạo file $wslcfg với memory=$mem ? (c = có / k = không)"
  if ($ans -match '^(c|co|có|y|yes)$') {
    $content = "[wsl2]`r`nmemory=$mem`r`nprocessors=2`r`nswap=1GB`r`n"
    [IO.File]::WriteAllText($wslcfg, $content, (New-Object System.Text.UTF8Encoding($false)))
    Ok "Đã tạo $wslcfg"
    Warn "Có hiệu lực sau khi tắt hẳn WSL: thoát Docker Desktop, chạy  wsl --shutdown , rồi chạy lại file này."
  }
}

# ---- 6. .env ------------------------------------------------------------------------
$envFile = Join-Path $PSScriptRoot ".env"
$old = @{}
if (Test-Path $envFile) {
  foreach ($line in Get-Content -LiteralPath $envFile) {
    if ($line -match '^\s*([A-Z_]+)=(.*)$') { $old[$Matches[1]] = $Matches[2] }
  }
}
# Command line wins, then what an earlier run wrote to .env, then the default.
function Pick($name, $given, $default) {
  if ("$given" -ne "") { return "$given" }
  if ($old.ContainsKey($name) -and $old[$name] -ne "") { return $old[$name] }
  return $default
}
$farm = Pick "FARM" "" (Join-Path $env:USERPROFILE "proxy-farm")
$uiPort = Pick "PORT" $(if ($Port -gt 0) { "$Port" } else { "" }) "8090"
$scan = Pick "SCAN" "" (Join-Path $env:USERPROFILE "Downloads")
$low = Pick "LOW_RESOURCE" $LowResource $(if ($ramGB -gt 0 -and $ramGB -lt 8) { "1" } else { "0" })
$maxA = Pick "MAX_ACTIVE" $MaxActive ""

foreach ($d in "secrets", "status", "configs", "data", "inbox") {
  New-Item -ItemType Directory -Force -Path (Join-Path $farm $d) | Out-Null
}
if (-not (Test-Path $scan)) { $scan = Join-Path $farm ".noscan"; New-Item -ItemType Directory -Force -Path $scan | Out-Null }

# The manager runs `docker run -v <host path>` from inside a Linux container, and the
# Docker Desktop daemon names C:\Users\... as /run/desktop/mnt/host/c/Users/...
function DaemonPath([string]$p) {
  $full = [IO.Path]::GetFullPath($p)
  if ($full -match '^([A-Za-z]):\\(.*)$') {
    return "/run/desktop/mnt/host/" + $Matches[1].ToLower() + "/" + ($Matches[2] -replace '\\', '/')
  }
  return ($full -replace '\\', '/')
}
$lines = @(
  "FARM=$farm",
  "FARM_HOST=$(DaemonPath $farm)",
  "PORT=$uiPort",
  "BIND=127.0.0.1",
  "SCAN=$scan",
  "LOW_RESOURCE=$low",
  "MAX_ACTIVE=$maxA",
  "# Port containers are created by the manager, not by compose; don't warn about them.",
  "COMPOSE_IGNORE_ORPHANS=true"
)
[IO.File]::WriteAllLines($envFile, $lines, (New-Object System.Text.UTF8Encoding($false)))
Ok "Đã ghi .env (dữ liệu ở $farm)"
if ($low -eq "1") { Ok "Chế độ máy yếu: BẬT (đổi được trong giao diện: Nâng cao > Cài đặt)" }

# ---- 7. Build + chạy -----------------------------------------------------------------
Say ""
Say "=== Đang build và khởi động (lần đầu mất khoảng 5–15 phút trên máy yếu, cần Internet) ==="
& docker compose build node manager
if ($LASTEXITCODE -ne 0) {
  Fail "Build image thất bại." @(
    "Kiểm tra kết nối Internet rồi chạy lại.",
    "Nếu báo hết dung lượng: Docker Desktop > Troubleshoot > Clean / Purge data, hoặc dọn ổ C:.")
}
$mgr = (& docker ps -aq -f "name=^pf-manager$" 2>$null)
$own = (& docker ps -aq -f "name=^pf-manager$" -f "label=com.docker.compose.project=proxy-farm" 2>$null)
if ($mgr -and -not $own) { & docker rm -f pf-manager *> $null }
& docker compose up -d manager
if ($LASTEXITCODE -ne 0) {
  Fail "Không khởi động được Proxy Farm." @(
    "Nếu báo cổng $uiPort đang bận: chạy lại với cổng khác:  powershell -ExecutionPolicy Bypass -File .\run.ps1 -Port 8091",
    "Xem log:  docker logs pf-manager")
}
& docker image prune -f --filter label=proxy-farm *> $null

$url = "http://127.0.0.1:$uiPort"
$ok = $false
for ($i = 0; $i -lt 30 -and -not $ok; $i++) {
  try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Uri "$url/api/status" | Out-Null; $ok = $true } catch { Start-Sleep -Seconds 2 }
}
Say ""
if ($ok) { Ok "Proxy Farm đang chạy: $url" } else { Warn "Proxy Farm chưa trả lời — thử mở $url sau ít giây." }
Say "   Tắt máy hay khởi động lại cũng không sao: mở Docker Desktop là Proxy Farm tự chạy lại."
if (-not $NoBrowser) { Start-Process $url }
