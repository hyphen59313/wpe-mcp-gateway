@echo off
rem 客户端里配置成 command 指向本文件即可（args 留空）。
rem 优先用 py launcher，回退到 PATH 里的 python。
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -m wpe_mcp %*
) else (
  python -m wpe_mcp %*
)
