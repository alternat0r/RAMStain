@echo off
rem ============================================================================
rem  RAMstain - publish a GitHub Release
rem
rem  Steps:
rem    1. Checks: git + gh available, gh logged in, no uncommitted changes.
rem    2. Builds Release x64 (build.bat), which bumps the minor version in
rem       src\version.h.
rem    3. Computes the SHA-256 of x64\Release\RAMstain.exe.
rem    4. Asks for confirmation, then commits src\version.h, tags vX.Y.Z,
rem       pushes the branch + tag, and creates the GitHub Release with
rem       RAMstain.exe attached and the SHA-256 in the release notes.
rem
rem  Usage:
rem      release.bat          publish a normal release
rem      release.bat draft    create the release as a draft (review on GitHub,
rem                           then publish it there)
rem
rem  If the build fails or you answer N at the prompt, src\version.h is
rem  restored, so the next attempt reuses the same version number.
rem ============================================================================
setlocal EnableExtensions
cd /d "%~dp0"

set "DRAFT="
if /I "%~1"=="draft" set "DRAFT=--draft"

set "EXE=x64\Release\RAMstain.exe"
set "NOTES=%TEMP%\ramstain_release_notes.md"

rem --- 1. Pre-flight checks ---------------------------------------------------
where git >nul 2>&1 || (echo [release] ERROR: git not found on PATH. & exit /b 1)
where gh  >nul 2>&1 || (echo [release] ERROR: GitHub CLI 'gh' not found on PATH. & exit /b 1)
gh auth status >nul 2>&1 || (echo [release] ERROR: gh is not logged in. Run: gh auth login & exit /b 1)

rem Release only committed source: refuse if tracked files have changes.
set "DIRTY="
for /f "delims=" %%L in ('git status --porcelain --untracked-files=no') do set "DIRTY=1"
if defined DIRTY (
    echo [release] ERROR: uncommitted changes. Commit or stash them first:
    git status --short --untracked-files=no
    exit /b 1
)

for /f "delims=" %%B in ('git branch --show-current') do set "BRANCH=%%B"
if not defined BRANCH (
    echo [release] ERROR: detached HEAD. Check out a branch first.
    exit /b 1
)

rem --- 2. Build (bumps the minor version) -------------------------------------
call "%~dp0build.bat" Release app
if errorlevel 1 (
    echo [release] Build failed - restoring src\version.h.
    git checkout -- src\version.h
    exit /b 1
)
if not exist "%EXE%" (
    echo [release] ERROR: %EXE% not found after build.
    git checkout -- src\version.h
    exit /b 1
)

rem Version from src\version.h:  #define RAMSTAIN_VER_STR   "1.3.0"
set "VER="
rem (literal match; the trailing space excludes the RAMSTAIN_VER_STR4 line)
for /f "tokens=3" %%V in ('findstr /b /c:"#define RAMSTAIN_VER_STR " src\version.h') do set "VER=%%~V"
if not defined VER (
    echo [release] ERROR: could not read RAMSTAIN_VER_STR from src\version.h.
    git checkout -- src\version.h
    exit /b 1
)
set "TAG=v%VER%"

rem Tag must not exist yet (locally or on GitHub).
git rev-parse -q --verify "refs/tags/%TAG%" >nul 2>&1 && (
    echo [release] ERROR: tag %TAG% already exists locally.
    git checkout -- src\version.h
    exit /b 1
)
for /f %%R in ('git ls-remote --tags origin "refs/tags/%TAG%"') do (
    echo [release] ERROR: tag %TAG% already exists on origin.
    git checkout -- src\version.h
    exit /b 1
)

rem --- 3. SHA-256 of the EXE --------------------------------------------------
set "SHA256="
for /f %%H in ('powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '%EXE%').Hash.ToLower()"') do set "SHA256=%%H"
if not defined SHA256 (
    echo [release] ERROR: could not compute SHA-256 of %EXE%.
    git checkout -- src\version.h
    exit /b 1
)

rem Release notes (Markdown). Written outside any ( ) block so the parentheses
rem and backticks in the text need no escaping.
> "%NOTES%" echo ## RAMstain %TAG%
>>"%NOTES%" echo.
>>"%NOTES%" echo **SHA-256** of `RAMstain.exe`:
>>"%NOTES%" echo.
>>"%NOTES%" echo ```
>>"%NOTES%" echo %SHA256%
>>"%NOTES%" echo ```
>>"%NOTES%" echo.
>>"%NOTES%" echo Verify after downloading:
>>"%NOTES%" echo.
>>"%NOTES%" echo ```
>>"%NOTES%" echo certutil -hashfile RAMstain.exe SHA256
>>"%NOTES%" echo ```
>>"%NOTES%" echo.
>>"%NOTES%" echo Portable single EXE: the signed WinPmem imager is built in (Apache 2.0, https://github.com/Velocidex/WinPmem). Run as Administrator.

rem --- 4. Confirm, then commit / tag / push / release -------------------------
echo.
echo ============================================================
echo   Release : %TAG% %DRAFT%
echo   Branch  : %BRANCH%  -^>  origin
echo   Asset   : %EXE%
echo   SHA-256 : %SHA256%
echo ============================================================
echo This will commit src\version.h, tag %TAG%, push to origin, and
echo create the GitHub Release.
choice /c YN /m "Publish"
if errorlevel 2 (
    echo [release] Cancelled - restoring src\version.h.
    git checkout -- src\version.h
    del "%NOTES%" >nul 2>&1
    exit /b 1
)

git add src\version.h || goto fail
git commit -m "Release %TAG%" || goto fail
git tag -a "%TAG%" -m "RAMstain %TAG%" || goto fail
git push origin "%BRANCH%" || goto fail
git push origin "%TAG%" || goto fail
gh release create "%TAG%" "%EXE%" --title "RAMstain %TAG%" --notes-file "%NOTES%" %DRAFT% || goto fail

del "%NOTES%" >nul 2>&1
echo.
echo [release] Published %TAG%
echo [release] SHA-256 RAMstain.exe: %SHA256%
exit /b 0

:fail
echo.
echo [release] FAILED at the step above. What has already happened stays done:
echo           check "git log -1", "git tag", and the GitHub Releases page, then
echo           finish by hand (e.g. rerun the failed push or "gh release create").
echo           Release notes kept at: %NOTES%
exit /b 1
