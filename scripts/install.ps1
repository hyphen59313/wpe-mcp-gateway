<#
.SYNOPSIS
  一次性安装 wpe-mcp-gateway：检查 Python、写配置、打印客户端片段、可选自检。

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Test
#>
param(
  [switch]$Test,
  [string]$ClientConfigPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Write-Host "项目目录：$root" -ForegroundColor Cyan

# ---- 1. 检查 Python ------------------------------------------------
$python = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
  $python = 'py -3'
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
  $python = 'python'
} else {
  Write-Host "没找到 Python。请先安装 Python 3.11+（https://www.python.org/downloads/windows/），安装时勾选 Add to PATH。" -ForegroundColor Red
  exit 1
}
$versionOutput = & cmd /c "$python --version" 2>&1
Write-Host "Python：$versionOutput（$python）" -ForegroundColor Green

# ---- 2. 写配置 ----------------------------------------------------
$dataDir = Join-Path $env:LOCALAPPDATA 'wpe-mcp'
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$configPath = Join-Path $dataDir 'config.toml'
if (Test-Path $configPath) {
  Write-Host "配置已存在，保留不动：$configPath" -ForegroundColor Yellow
} else {
  Copy-Item (Join-Path $root 'config.example.toml') $configPath
  Write-Host "已生成配置：$configPath" -ForegroundColor Green
}

# ---- 3. 检测 WPE 连接器 -------------------------------------------
$connector = 'C:\WPE64DB\McpServer\WPEMcpServer.exe'
if (Test-Path $connector) {
  Write-Host "已找到 WPE 连接器：$connector" -ForegroundColor Green
} else {
  Write-Host "暂未找到 $connector" -ForegroundColor Yellow
  Write-Host "  → 先装 WPE x64 2.3+（www.wpe64.com），启动一次，连接器会自动同步到该路径；" -ForegroundColor Yellow
  Write-Host "  → WPE 必须保持运行，网关才会连得上。" -ForegroundColor Yellow
}

# ---- 4. 自检 ------------------------------------------------------
if ($Test) {
  Write-Host "`n=== 自检 ===" -ForegroundColor Cyan
  Push-Location $root
  & cmd /c "$python -m wpe_mcp --selftest --log-level info"
  Pop-Location
}

# ---- 5. 客户端配置片段 --------------------------------------------
$launcher = Join-Path $root 'wpe-mcp.cmd'
$launcherEscaped = $launcher.Replace('\', '\\')
$snippet = @"
{
  "mcpServers": {
    "wpe": {
      "command": "$launcherEscaped",
      "args": []
    }
  }
}
"@
Write-Host "`n=== 把下面这段合并进你的 MCP 客户端配置 ===" -ForegroundColor Cyan
Write-Host $snippet
if ($ClientConfigPath) {
  $snippet | Out-File -Encoding utf8 -NoNewline $ClientConfigPath
  Write-Host "已写入：$ClientConfigPath" -ForegroundColor Green
}
Write-Host "`n完成。启动顺序：先开 WPE（MCP 总开关打开）→ 再启动 AI 客户端。" -ForegroundColor Green
