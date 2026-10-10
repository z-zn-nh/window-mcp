@echo off
rem cloudflared tunnel login —— 授权 example.com 的 zone。
rem 必须在浏览器里选 example.com 并点 Authorize，cert.pem 才会落到 ~/.cloudflared。
cd /d "D:\window-mcp-v2"
"D:\window-mcp\tools\cloudflared.exe" tunnel login > "D:\window-mcp-v2\logs\cf-login.log" 2>&1
echo exit=%errorlevel% >> "D:\window-mcp-v2\logs\cf-login.log"
