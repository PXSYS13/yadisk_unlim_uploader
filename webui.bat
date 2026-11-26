@echo off
setlocal
if exist "%SystemRoot%\System32\chcp.com" "%SystemRoot%\System32\chcp.com" 65001 >nul 2>&1
title Yandex.Disk Unlim Uploader
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

REM uv version and SHA-256 of official Windows archives (github.com/astral-sh/uv/releases).
REM All Windows tools are invoked via %SystemRoot%\System32 to prevent CWD binary hijacking.
set "UV_VERSION=0.13.4"
set "UV_ZIP_SHA256_X64=ccec7508a07d9933d7cb1261880633efcf1f30d6e6eddab21823f1dae6f23225"
set "UV_ZIP_SHA256_ARM64=c4bc5a9534b2bb6a12fe29ea748445e1a6f9cb7bb275211c4fb74c52ecf317a5"
set "UV_ZIP_SHA256_X86=b450f623b34bf85322bbc656d5879915acd818dc5b05fc2d33e343da26799e37"

set "SYS_CURL=%SystemRoot%\System32\curl.exe"
set "SYS_TAR=%SystemRoot%\System32\tar.exe"
set "SYS_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "SYS_WHERE=%SystemRoot%\System32\where.exe"

echo ============================================================
echo   Yandex.Disk Unlim Uploader
echo ============================================================
echo.

set "UV=.uv\uv.exe"
if exist "%UV%" goto :run
set "UV=%USERPROFILE%\.local\bin\uv.exe"
if exist "%UV%" goto :run
if exist "%SYS_WHERE%" (
    for /f "delims=" %%I in ('"%SYS_WHERE%" uv 2^>nul') do (
        if /i not "%%~dpI"=="%~dp0" (
            set "UV=%%I"
            goto :run
        )
    )
)
set "UV=.uv\uv.exe"

echo [setup] uv not found. Downloading uv %UV_VERSION% into .uv - runs ONLY ONCE...
echo.
if not exist "%SYS_CURL%" goto :uvold
if not exist "%SYS_TAR%" goto :uvold
if not exist "%SYS_PS%" goto :uvold
set "UV_ARCH=x86_64"
set "UV_ZIP_SHA256=%UV_ZIP_SHA256_X64%"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set "UV_ARCH=i686"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "UV_ARCH=aarch64"
if /i "%PROCESSOR_ARCHITEW6432%"=="ARM64" set "UV_ARCH=aarch64"
if "%UV_ARCH%"=="i686" set "UV_ZIP_SHA256=%UV_ZIP_SHA256_X86%"
if "%UV_ARCH%"=="aarch64" set "UV_ZIP_SHA256=%UV_ZIP_SHA256_ARM64%"
set "UV_ZIP=.uv\uv-%UV_VERSION%.zip"
set "UV_ZIP_URL=https://github.com/astral-sh/uv/releases/download/%UV_VERSION%/uv-%UV_ARCH%-pc-windows-msvc.zip"
if not exist .uv mkdir .uv
"%SYS_CURL%" --proto =https --tlsv1.2 --fail --location --retry 3 --progress-bar --output "%UV_ZIP%" "%UV_ZIP_URL%"
if errorlevel 1 goto :uvfail
"%SYS_PS%" -NoProfile -NonInteractive -Command "if ((Get-FileHash -Algorithm SHA256 -LiteralPath $env:UV_ZIP).Hash -ne $env:UV_ZIP_SHA256) { exit 1 }"
if errorlevel 1 goto :uvbad
"%SYS_TAR%" -xf "%UV_ZIP%" -C .uv uv.exe
if errorlevel 1 goto :uvfail
del "%UV_ZIP%" >nul 2>&1
if not exist "%UV%" goto :uvfail
echo.
echo [OK] uv installed.
echo.

:run
echo [*] Starting via uv (first run downloads Python and dependencies, 1-2 min)...
echo.
"%UV%" run --locked --no-dev webui.py
goto :done

:uvbad
del "%UV_ZIP%" >nul 2>&1
echo [!] Checksum mismatch for uv archive. Install uv manually: https://docs.astral.sh/uv/getting-started/installation/
pause
exit /b 1

:uvold
echo [!] Windows version lacks System32 curl.exe, tar.exe or powershell.exe. Install uv manually: https://docs.astral.sh/uv/getting-started/installation/
pause
exit /b 1

:uvfail
del "%UV_ZIP%" >nul 2>&1
echo [!] Could not install uv automatically. Install uv manually: https://docs.astral.sh/uv/getting-started/installation/
pause
exit /b 1

:done
echo.
echo ============================================================
echo   Server stopped.
echo ============================================================
pause
