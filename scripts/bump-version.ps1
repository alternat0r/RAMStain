# =============================================================================
#  RAMstain - bump the minor version before each build.
#
#  Called by the MSBuild PreBuildEvent in RAMstain.vcxproj (so it runs for
#  build.bat and Visual Studio builds alike). Reads src\version.h, increments
#  RAMSTAIN_VER_MINOR, resets RAMSTAIN_VER_PATCH to 0, and rewrites the file.
# =============================================================================
param(
    [string]$Header = (Join-Path $PSScriptRoot "..\src\version.h")
)
$ErrorActionPreference = "Stop"

$text = [System.IO.File]::ReadAllText($Header)
function Get-Num([string]$name) {
    $m = [regex]::Match($text, "#define\s+$name\s+(\d+)")
    if (-not $m.Success) { throw "bump-version: $name not found in $Header" }
    return [int]$m.Groups[1].Value
}
$major = Get-Num "RAMSTAIN_VER_MAJOR"
$minor = (Get-Num "RAMSTAIN_VER_MINOR") + 1
$patch = 0
$ver   = "$major.$minor.$patch"

$lines = @(
    "// RAMstain version - single source of truth for the EXE version resource",
    "// (ramstain.rc), the UI footer and the .meta sidecar (RAMstain.cpp).",
    "//",
    "// GENERATED: scripts\bump-version.ps1 rewrites this file before every build",
    "// (MSBuild PreBuildEvent), incrementing the minor number. To change the major",
    "// version or reset the minor, edit the numbers below; the next build continues",
    "// from them.",
    "#ifndef RAMSTAIN_VERSION_H",
    "#define RAMSTAIN_VERSION_H",
    "",
    "#define RAMSTAIN_VER_MAJOR $major",
    "#define RAMSTAIN_VER_MINOR $minor",
    "#define RAMSTAIN_VER_PATCH $patch",
    "",
    "#define RAMSTAIN_VER_STR   `"$ver`"",
    "#define RAMSTAIN_VER_STR4  `"$ver.0`"",
    "#define RAMSTAIN_VER_WSTR  L`"$ver`"",
    "",
    "#endif // RAMSTAIN_VERSION_H",
    ""
)
[System.IO.File]::WriteAllText($Header, ($lines -join "`r`n"), [System.Text.Encoding]::ASCII)
Write-Host "[version] RAMstain $ver"
