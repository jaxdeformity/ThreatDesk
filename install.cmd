@echo off
rem Wrapper so install.ps1 runs regardless of the PowerShell execution policy.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
