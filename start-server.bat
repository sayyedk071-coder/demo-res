@echo off
cd /d "%~dp0"
set NODE_ENV=development
set PORT=3400
set WEB_CONCURRENCY=1
node server.js
pause
