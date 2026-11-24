@echo off
title Kestrel
cd /d "%~dp0"
echo Starting Kestrel at http://127.0.0.1:8787 ...
echo Keep this window open. Close it to stop Kestrel.
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:8787"
node server/index.js
pause
