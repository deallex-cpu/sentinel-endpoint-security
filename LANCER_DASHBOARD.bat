@echo off
title SENTINEL — Endpoint Security Monitoring
color 03

:: Vérifier droits admin
net session >nul 2>&1
if %errorLevel% neq 0 (
  echo.
  echo  [SENTINEL] Relancement en mode administrateur...
  powershell -Command "Start-Process '%~f0' -Verb RunAs"
  exit /b
)

echo.
echo  ========================================
echo    SENTINEL — ENDPOINT SECURITY
echo    Serveur sur http://localhost:8888
echo  ========================================
echo.
cd /d "%~dp0"
node server.js
pause
