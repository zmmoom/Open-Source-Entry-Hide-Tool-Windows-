@echo off
setlocal enableextensions
cd /d "%~dp0"

echo ============================================================
echo  DeviceLink build and test
echo ============================================================
echo.

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo [ERROR] csc.exe not found.
    goto hold
)

echo [*] Compiler: %CSC%
"%CSC%" /nologo /target:exe /platform:x64 /out:DeviceLink.exe DeviceLink.cs
if errorlevel 1 (
    echo [ERROR] Compile failed.
    goto hold
)

echo [*] Build OK: %CD%\DeviceLink.exe
echo.
echo Connect iPhone, unlock it, tap Trust, then:
pause

set "DLLDIR=%~dp0..\proven_native_lite"
if exist "%DLLDIR%\MobileDevice.dll" (
    echo [*] Apple DLL dir: %DLLDIR%
    DeviceLink.exe "%DLLDIR%"
) else (
    echo [*] Running without explicit DLL dir.
    DeviceLink.exe
)

echo.
echo [Exit code %ERRORLEVEL%]
echo Send me the JSON line above.

:hold
echo.
pause
endlocal
