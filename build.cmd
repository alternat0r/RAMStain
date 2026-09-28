# Builds RAMstain with Visual Studio 2022 (MSBuild).
# Usage:  build.cmd [Release|Debug]   (default: Release)
setlocal
set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Release
set VS=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe
"%VS%" "%~dp0RAMstain.vcxproj" /p:Configuration=%CONFIG% /p:Platform=x64 /m /nologo /v:m
exit /b %ERRORLEVEL%
