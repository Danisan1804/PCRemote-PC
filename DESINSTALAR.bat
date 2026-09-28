@echo off
schtasks /Delete /TN "PCRemoteLauncher" /F >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000"') do taskkill /F /PID %%a >nul 2>&1
echo PC Remote eliminado del arranque.
pause
