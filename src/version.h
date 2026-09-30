// RAMstain version - single source of truth for the EXE version resource
// (ramstain.rc), the UI footer and the .meta sidecar (RAMstain.cpp).
//
// GENERATED: scripts\bump-version.ps1 rewrites this file before every build
// (MSBuild PreBuildEvent), incrementing the minor number. To change the major
// version or reset the minor, edit the numbers below; the next build continues
// from them.
#ifndef RAMSTAIN_VERSION_H
#define RAMSTAIN_VERSION_H

#define RAMSTAIN_VER_MAJOR 1
#define RAMSTAIN_VER_MINOR 11
#define RAMSTAIN_VER_PATCH 0

#define RAMSTAIN_VER_STR   "1.11.0"
#define RAMSTAIN_VER_STR4  "1.11.0.0"
#define RAMSTAIN_VER_WSTR  L"1.11.0"

#endif // RAMSTAIN_VERSION_H
