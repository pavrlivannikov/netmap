@echo off
chcp 65001 >nul
echo ============================================
echo  NetMap — Portable EXE Builder
echo ============================================

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.10+ not found. Install from python.org
    pause
    exit /b 1
)

echo [1/4] Python found:
python --version

echo [2/4] Installing dependencies...
python -m pip install netifaces pysnmp pyinstaller --quiet 2>nul
if %errorlevel% neq 0 (
    echo [WARN] Some packages may not have installed. Continuing...
)

echo [3/4] Auto-incrementing build...
set /p VER=<VERSION
for /f "tokens=1,2,3 delims=." %%a in ("%VER%") do (
    set MAJOR=%%a
    set MINOR=%%b
    set BUILD=%%c
)
set /a NEW_BUILD=%BUILD%+1
set NEW_VER=%MAJOR%.%MINOR%.%NEW_BUILD%
echo %NEW_VER%> VERSION

echo [4/4] Building netmap-v%NEW_VER%.exe...
pyinstaller --onefile --windowed --name=netmap-v%NEW_VER% --add-data "VERSION;." netmap_gui.py

if %errorlevel% equ 0 (
    echo.
    echo ============================================
    echo  DONE: dist\netmap-v%NEW_VER%.exe
    echo ============================================
) else (
    echo.
    echo [ERROR] Build failed. Check errors above.
)

pause
