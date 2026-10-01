@echo off
rem ============================================================================
rem  RAMstain - build script (replaces build.cmd)
rem
rem  Builds the RAMstain application (x64) and compiles the diagnostic tools
rem  in tools\*.c.
rem
rem  Usage (arguments in any order):
rem      build.bat              Release x64 : app + tools
rem      build.bat Debug        Debug  x64  : app + tools
rem      build.bat app          Release x64 : app only (skip tools)
rem      build.bat bump         bump the minor version first (for a release)
rem
rem  Ordinary builds do not change the version; only `bump` does.
rem
rem  Requires Visual Studio 2022 (Desktop development with C++).
rem  Adjust VSDIR below if you use a different edition (Professional, etc.).
rem ============================================================================
setlocal

set "CONFIG=Release"
set "APPMODE=no"
set "BUMP=no"
:args
if "%~1"=="" goto argsdone
if /I "%~1"=="Debug"   set "CONFIG=Debug"
if /I "%~1"=="Release" set "CONFIG=Release"
if /I "%~1"=="app"     set "APPMODE=yes"
if /I "%~1"=="bump"    set "BUMP=yes"
shift
goto args
:argsdone

if /I "%BUMP%"=="yes" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\bump-version.ps1" -Header "%~dp0src\version.h"
    if errorlevel 1 ( echo [build] Version bump FAILED. & exit /b 1 )
)

set "VSDIR=C:\Program Files\Microsoft Visual Studio\2022\Community"
set "VCVARS=%VSDIR%\VC\Auxiliary\Build\vcvars64.bat"
set "MSBUILD=%VSDIR%\MSBuild\Current\Bin\MSBuild.exe"

if not exist "%VCVARS%" (
    echo [build] ERROR: vcvars64.bat not found:
    echo         %VCVARS%
    echo [build] If you use a different VS edition, change VSDIR in this script.
    exit /b 1
)
call "%VCVARS%" >nul 2>&1
set "FAILED=0"

echo.
echo === [1/2] RAMstain app  - %CONFIG% - x64 ===
"%MSBUILD%" "%~dp0RAMstain.vcxproj" /p:Configuration=%CONFIG% /p:Platform=x64 /m /nologo /v:m
if errorlevel 1 (
    echo [build] App build FAILED.
    set "FAILED=1"
)

if /I "%APPMODE%"=="yes" goto report

echo.
echo === [2/2] Diagnostic tools - tools\*.c ===
for %%F in ("%~dp0tools\*.c") do (
    if not exist "%%F" continue
    echo   %%~nxF
    cl /nologo /O2 /W3 "%%F" /Fe:"%%~dpnF.exe" /link /SUBSYSTEM:CONSOLE advapi32.lib kernel32.lib user32.lib gdi32.lib
    if errorlevel 1 (
        echo [build]   FAILED: %%~nxF
        set "FAILED=1"
    )
)

:report
echo.
if "%FAILED%"=="1" (
    echo [build] BUILD FAILED - see errors above.
    exit /b 1
)
echo [build] OK. App: x64\%CONFIG%\RAMstain.exe
exit /b 0
