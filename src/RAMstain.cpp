// ============================================================================
//  RAMstain - Compact Physical Memory Capture (Win32, zero dependencies)
//
//  Captures physical RAM via the signed Velocidex WinPmem imager (default):
//  the imager loads its signed kernel driver, writes the image, and unloads.
//  RAMstain adds SHA-256 and the .meta evidence sidecar. No registration, no
//  account, no network. Offline by design.
//
//  An experimental driverless path (OpenProcess(PID -1) + ReadProcessMemory)
//  is kept as an opt-in fallback. It is not a documented Windows API: on
//  current Windows, OpenProcess(-1) fails with error 87 exactly as it does for
//  any nonexistent PID, so expect it to fail.
//
//  Output:
//    <name>.raw   physical memory image, 4 KiB page-aligned
//    <name>.meta  capture metadata (host, OS, kernel, size, SHA-256)
//    <name>.log   timestamped run log (options, steps, errors, results); appended per run
//
//  UI: modern flat theme (dark header band, cards, rounded owner-drawn
//      buttons, themed progress bar), Disclaimer / Privacy / Terms dialogs.
//
//  CLI:
//    RAMstain.exe ["C:\path\to\dump.raw"]     pre-fill the save path
//    RAMstain.exe --driver <imager.exe>       use an explicit WinPmem imager
//    RAMstain.exe --no-driver                 start with the driverless path selected
//    RAMstain.exe --pagefile                  also collect pagefile.sys
//    RAMstain.exe --hiberfil                  also collect hiberfil.sys
//    RAMstain.exe --swapfile                  also collect swapfile.sys
//    RAMstain.exe --system-files              collect pagefile, hibernation file and swapfile
//    RAMstain.exe --no-memory                 no memory image (system files only)
//    RAMstain.exe --selftest ["C:\path\out"]  synthetic 512 MiB pipeline test
//    RAMstain.exe --help                      list the options (also -h, /?)
//
//  Build: MSVC (Visual Studio 2022), x64, static CRT
// ============================================================================
#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#define _WIN32_IE 0x0700
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winioctl.h>
#include <windowsx.h>
#include <shellapi.h>
#include <commdlg.h>
#include <commctrl.h>
#include <process.h>
#include <sddl.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cstdio>
#include <cstdint>
#include "sha256.h"
#include "util.h"
#include "hash_pipeline.h"
#include "run_log.h"
#include "ntfs_raw.h"
#include "verify.h"
#include "legal.h"
#include "resource.h"
#include "version.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// WM_DRAWITEM: the control type is in DRAWITEMSTRUCT->CtlType, not wParam.
// The SDK does not define DT_BUTTON; empirically CtlType == 4 for BS_OWNERDRAW
// buttons on this OS (== ODT_BUTTON's numeric value).
#define DT_BUTTON 4

// ---------------------------------------------------------------------------
//  Control / window IDs
// ---------------------------------------------------------------------------
#define IDC_EDIT_PATH    1001
#define IDC_BTN_BROWSE   1002
#define IDC_BTN_CAPTURE  1003
#define IDC_BTN_CLOSE    1004
#define IDC_BTN_DISC     1005
#define IDC_BTN_PRIV     1006
#define IDC_BTN_TERMS    1007
#define IDC_PROGRESS     1008
#define IDC_CHK_TOP      1009
#define IDC_CHK_DRIVER   1010
#define IDC_CMB_SPLIT    1011
#define IDC_BTN_SPLITHELP 1012
#define IDC_CHK_PAGEFILE 1013
#define IDC_CHK_HIBERFIL 1014
#define IDC_CHK_MEMORY   1015
#define IDC_CHK_SWAPFILE 1016

#define IDC_SUB_TEXT     2001
#define IDC_SUB_PRIMARY  2002
#define IDC_SUB_SECOND   2003
#define IDC_SUB_OK       2004
#define IDC_SUB_COPY     2005

// System-menu command (title-bar icon menu). Must be below 0xF000 with the low
// four bits clear, as Windows uses those bits in WM_SYSCOMMAND.
#define IDM_ABOUT        0x0010

#define WM_APP_PROGRESS (WM_APP + 1)   // wParam = percent, lParam = bytes done in this phase
#define WM_APP_FINISHED (WM_APP + 2)
#define WM_APP_PHASE    (WM_APP + 3)   // wParam = CapturePhase, lParam = expected total bytes (0 = unknown)

enum class CapturePhase { Capturing = 0, Hashing = 1, Splitting = 2, Collecting = 3 };

static const wchar_t* kWindowClass = L"RAMstain.MainWindow";
static const wchar_t* kSubClass    = L"RAMstain.SubWindow";
static const wchar_t* kVersionStr  = RAMSTAIN_VER_WSTR;   // src/version.h (bumped each build)

// ---------------------------------------------------------------------------
//  Theme (light, flat, modern)
// ---------------------------------------------------------------------------
struct Theme {
    COLORREF bg, header, headerSub, text, muted, label;
    COLORREF accent, accentHover, accentDown, secBorder, secText, secFill;
    COLORREF secHoverFill, secDownFill;
    COLORREF danger, dangerHover, dangerDown, ok, white, disabledFill, disabledText;
    Theme() {
        bg           = RGB(248, 250, 252);
        header       = RGB(15, 23, 42);
        headerSub    = RGB(148, 163, 184);
        text         = RGB(15, 23, 42);
        muted        = RGB(100, 116, 139);
        label        = RGB(100, 116, 139);
        accent       = RGB(37, 99, 235);
        // Hover colors are deliberately distinct from the resting color so the
        // Capture / Stop / Close buttons visibly react to the pointer.
        accentHover  = RGB(30, 64, 175);    // Capture: blue -> deep blue
        accentDown   = RGB(23, 37, 84);
        secBorder    = RGB(203, 213, 225);
        secText      = RGB(30, 41, 59);
        secFill      = RGB(255, 255, 255);
        secHoverFill = RGB(219, 234, 254);  // Close: white -> light blue, blue border + text
        secDownFill  = RGB(191, 219, 254);
        danger       = RGB(220, 38, 38);
        dangerHover  = RGB(153, 27, 27);    // Stop: red -> dark red
        dangerDown   = RGB(127, 29, 29);
        ok           = RGB(5, 150, 105);
        white        = RGB(255, 255, 255);
        disabledFill = RGB(241, 245, 249);
        disabledText = RGB(148, 163, 184);
    }
};
static Theme C;

static HBRUSH g_brBg = nullptr, g_brHeader = nullptr, g_brWhite = nullptr;
static HBRUSH g_brLine = nullptr, g_brFooter = nullptr;  // separators, footer strip
static HPEN   g_penEditBorder = nullptr, g_penNull = nullptr;
static HFONT  g_fTitle = nullptr, g_fBody = nullptr, g_fLabel = nullptr, g_fSmall = nullptr, g_fEdit = nullptr;
static HFONT  g_fText = nullptr;  // normal-weight body text for dialog/document windows
static HFONT  g_fFoot = nullptr;  // header subtitle / footer text

// Main window layout, in 96-dpi pixels (scaled with Sc()). Client area is
// kDesignW x kDesignH; see DrawMain and WM_CREATE for the rows.
static const int kDesignW = 520, kDesignH = 426;
static const int kPad     = 16;   // outer margin
static const int kHeaderH = 48;   // dark header band
static const int kCol2    = 268;  // x of the second column (Host/OS, driver checkbox)
static const int kBrowseW = 80;   // Browse button width
static const int kFooterY = 398;  // top of the footer strip
// Case details row: Case number, Examiner, Notes (x, width).
static const struct { int x, w; } kCaseFields[] = { { 16, 140 }, { 164, 150 }, { 322, 182 } };
static HICON  g_hIcon = nullptr;
static HICON  g_hIconAbout = nullptr;   // larger icon for the About dialog (loaded on first use)

static HWND   g_hwnd = nullptr;
static HWND   g_editPath, g_editCase, g_editExaminer, g_editNotes, g_lblCase, g_btnBrowse, g_btnCapture, g_btnClose, g_progress,
              g_btnDisc, g_btnPriv, g_btnTerms, g_chkTop, g_chkDriver, g_cmbSplit,
              g_btnSplitHelp, g_lblSave, g_lblSplit, g_lblCollect,
              g_chkMemory, g_chkPagefile, g_chkHiberfil, g_chkSwapfile;
static HWND   g_lastFocus = nullptr;    // control to refocus when the window is reactivated
static HANDLE g_stopEvent = nullptr;
static bool   g_capturing = false;
// --auto: capture at once with no dialogs, print the result, exit with a code
// (see AutoExitCode). g_exitCode is the process exit code (WM_DESTROY).
static bool   g_auto = false;
static int    g_exitCode = 0;
static bool   g_finishPending = false; // capture finished while a dialog was open
static bool   g_closeAfterStop = false;// user chose "Stop and close": exit when the capture ends
static bool   g_selftest  = false;
static bool   g_topmost   = false;   // "Always on top" (default off)
static bool   g_driverMode = false;  // resolved per capture from the "Use WinPmem driver" checkbox
static bool   g_driverDefault = true;// initial checkbox state (on; --no-driver turns it off)
static bool   g_driverWarned = false;// show the driver warning once per session
static std::wstring g_driverPath;    // explicit imager path from --driver <path>
static std::wstring g_cliPath;
static UINT64 g_splitBytes = 0;      // part size for this capture (0 = no split); set in OnCapture
static UINT   g_cliSplitMB = 0;      // --split <MB> from the command line (0 = not given)
// "Also collect" options for this run (resolved from the checkboxes / CLI in
// OnCapture; g_cliCollect* is the command-line preselect for the checkboxes).
static bool   g_collectPagefile = false;
static bool   g_collectHiberfil = false;
static bool   g_collectSwapfile = false;
static bool   g_cliCollectPagefile = false;
static bool   g_cliCollectHiberfil = false;
static bool   g_cliCollectSwapfile = false;
// Memory image for this run (off = system files only); g_cliNoMemory is the
// --no-memory preselect for its checkbox.
static bool   g_captureMemory = true;
static bool   g_cliNoMemory = false;
// Case details for this run (resolved from the fields in OnCapture; one line
// each, may be empty) and their --case / --examiner / --notes preselects.
static std::wstring g_caseNumber, g_caseExaminer, g_caseNotes;
static std::wstring g_cliCase, g_cliExaminer, g_cliNotes;

static std::wstring g_status;        // status line text
static COLORREF     g_statusColor;   // status line color
static CapturePhase g_phase = CapturePhase::Capturing; // current worker phase (UI thread)
static UINT64       g_phaseTotal = 0;                  // expected bytes for g_phase (0 = unknown)

enum class BtnStyle { Primary, Secondary, Danger, Link, Help };  // Help = small round "?"
struct BtnState { BtnStyle style; bool hover; };
static std::map<HWND, BtnState> g_btns;

// One file of a split image (<base>.001, <base>.002, ...).
struct SplitPart {
    std::wstring path;
    UINT64       bytes = 0;
    std::string  sha256;             // empty when no hashes were computed
};

// The system files RAMstain can collect, in collection order. Each is
// <volume>\<name>.sys, copied to <image base>__<name>.raw (see SysName).
enum class SysKind { Pagefile, Hiberfil, Swapfile };
static const SysKind kSysKinds[] = { SysKind::Pagefile, SysKind::Hiberfil, SysKind::Swapfile };

static const wchar_t* SysName(SysKind k) {
    return k == SysKind::Pagefile ? L"pagefile" : k == SysKind::Hiberfil ? L"hiberfil" : L"swapfile";
}
static const wchar_t* SysLabel(SysKind k) {
    return k == SysKind::Pagefile ? L"Pagefile" : k == SysKind::Hiberfil ? L"Hibernation file" : L"Swapfile";
}

// One system file collected alongside the memory image (pagefile.sys,
// hiberfil.sys or swapfile.sys), copied in full with a single hash pass.
struct SysFileCapture {
    SysKind      kind = SysKind::Pagefile;
    std::wstring source;             // location found on this system (empty if not present)
    std::wstring path;               // the collected copy (empty if not collected)
    UINT64       bytes = 0;
    std::string  sha256;             // empty when no hash was computed
    std::wstring method;             // how it was read (empty if never opened)
    FILETIME     startUtc = {};      // collection start (UTC)
    FILETIME     endUtc = {};        // collection end (UTC)
    std::wstring metaPath;           // <path>.meta sidecar (empty if not written)
    std::wstring error;              // user-facing note when collection failed (empty on success)
    bool         absent = false;     // the file does not exist on this system (nothing to collect)
};

struct CaptureResult {
    bool      ok = false;
    bool      cancelled = false;         // Stop pressed during capture (partial image, no hashes)
    bool      hashStopped = false;       // Stop pressed while hashing a complete image (no hashes)
    UINT      errCode = 0;
    UINT64    pagesWritten = 0;
    UINT64    bytesWritten = 0;
    double    seconds = 0.0;
    std::wstring error;              // user-facing (empty on success)
    FILETIME     startUtc = {};      // capture start (UTC)
    FILETIME     endUtc = {};        // image data complete, before hashing/splitting (UTC)
    std::string  sha256;             // whole image; empty when not computed
    std::wstring path;
    std::wstring metaPath;
    std::wstring method;             // "WinPmem kernel driver ..." (empty = driverless path)
    std::vector<std::string> partSha256;  // per g_splitBytes slice, filled while hashing
    std::vector<SplitPart>   parts;  // non-empty once the image has been split
    std::wstring splitError;         // split failed part-way (image data still intact)
    std::vector<SysFileCapture> sysfiles;  // pagefile / hibernation files collected alongside
};

static CaptureResult* g_activeResult = nullptr;

// ---------------------------------------------------------------------------
//  Small helpers
// ---------------------------------------------------------------------------
static int Sc(int v, int dpi) { return MulDiv(v, dpi, 96); }

static void SetTextW(HWND h, const std::wstring& s) { SetWindowTextW(h, s.c_str()); }

static std::wstring GetTextW(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring s(n, L'\0');
    if (n > 0) GetWindowTextW(h, &s[0], n + 1);
    return s;
}

static void TrimRight(std::wstring& s) {
    while (!s.empty() && (s.back() == L' ' || s.back() == L'\t' ||
                          s.back() == L'\r' || s.back() == L'\n'))
        s.pop_back();
}



static std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH] = L"";
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L".";
    std::wstring p(buf, n);
    size_t sl = p.find_last_of(L"\\/");
    return (sl == std::wstring::npos) ? L"." : p.substr(0, sl);
}

static std::wstring MakeTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t b[32];
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"%04d%02d%02d_%02d%02d%02d",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}

// Default image file name: the host name, e.g. "WS-01.raw". Each capture goes
// into its own RAMstain_<timestamp> folder (see RunFolderFor), so the file
// name itself needs no timestamp.
static std::wstring GetComputerName();
static std::wstring DefaultDumpName() {
    std::wstring host = GetComputerName();
    return (host.empty() ? std::wstring(L"memory") : host) + L".raw";
}

static std::wstring DefaultDumpPath() {
    return GetExeDir() + L"\\" + DefaultDumpName();
}

static void StripExtensionInPlace(std::wstring& p) {
    size_t d = p.find_last_of(L'.');
    size_t s = p.find_last_of(L"\\/");
    if (d != std::wstring::npos && (s == std::wstring::npos || d > s)) p.erase(d);
}

static double GetTotalRamGB() {
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
        return (double)ms.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
    return 0.0;
}

static std::wstring GetComputerName() {
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = L"";
    DWORD n = _countof(buf);   // buffer size incl. the terminating NUL
    if (GetComputerNameW(buf, &n)) return std::wstring(buf, n);
    return L"unknown";
}

// Reliable version info (GetVersionEx is version-limited on Win8+).
static bool GetOsVersionRaw(DWORD& major, DWORD& minor, DWORD& build) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    typedef LONG(NTAPI* FnRtlGetVersion)(PRTL_OSVERSIONINFOW);
    FnRtlGetVersion fn = (FnRtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion");
    if (!fn) return false;
    RTL_OSVERSIONINFOW vi;
    ZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn(&vi) != 0) return false;
    major = vi.dwMajorVersion;
    minor = vi.dwMinorVersion;
    build = vi.dwBuildNumber;
    return true;
}

static std::wstring GetOsVersionString() {
    DWORD ma, mi, b;
    if (GetOsVersionRaw(ma, mi, b))
        return L"Windows " + std::to_wstring(ma) + L"." + std::to_wstring(mi) +
               L" build " + std::to_wstring(b);
    return L"Windows (version unknown)";
}

static std::wstring GetKernelVersionString() {
    DWORD ma, mi, b;
    if (GetOsVersionRaw(ma, mi, b))
        return L"NT " + std::to_wstring(ma) + L"." + std::to_wstring(mi) + L"." + std::to_wstring(b);
    return L"NT (unknown)";
}

static std::wstring FormatDuration(double sec) {
    if (sec <= 0) return L"0s";
    int h = (int)(sec / 3600.0);
    int m = (int)(sec / 60.0) % 60;
    int s = (int)(sec) % 60;
    wchar_t b[48];
    if (h > 0) _snwprintf_s(b, _countof(b), _TRUNCATE, L"%dh %dm %ds", h, m, s);
    else if (m > 0) _snwprintf_s(b, _countof(b), _TRUNCATE, L"%dm %ds", m, s);
    else _snwprintf_s(b, _countof(b), _TRUNCATE, L"%ds", s);
    return b;
}

static std::wstring FormatGB(UINT64 bytes) {
    wchar_t b[32];
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"%.1f GB",
                 (double)bytes / (1024.0 * 1024.0 * 1024.0));
    return b;
}

// Free space on the volume containing `path`.
// Free space for a file that will be written at path. The folders on the way
// may not exist yet (each capture creates its own run folder, plus any missing
// parents), so measure the nearest folder that does exist - it is on the same
// volume unless a missing folder would be a mount point, which it cannot be.
static bool GetVolumeFreeBytes(const std::wstring& path, UINT64& freeBytes) {
    std::wstring dir = path;
    for (;;) {
        size_t sl = dir.find_last_of(L"\\/");
        if (sl == std::wstring::npos) return false;
        dir.erase(sl);                                     // parent folder
        if (dir.empty() || dir == L"\\") return false;     // ran out (e.g. "\\server")
        std::wstring probe = (dir.size() == 2 && dir[1] == L':') ? dir + L"\\" : dir;
        DWORD a = GetFileAttributesW(probe.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) {
            ULARGE_INTEGER avail = {0}, total = {0}, totalFree = {0};
            if (probe.back() != L'\\') probe += L"\\";
            if (!GetDiskFreeSpaceExW(probe.c_str(), &avail, &total, &totalFree))
                return false;
            freeBytes = avail.QuadPart;
            return true;
        }
    }
}

// ---------------------------------------------------------------------------
//  Privileges
// ---------------------------------------------------------------------------
static void EnableSeDebugPrivilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;
    LUID luid;
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }
    CloseHandle(tok);
}

// ---------------------------------------------------------------------------
//  Capture core
// ---------------------------------------------------------------------------
static void FillSynthetic(BYTE* buf, size_t n, UINT64 off) {
    for (size_t i = 0; i < n; ++i)
        buf[i] = (BYTE)((off + i) ^ ((off + i) >> 8) ^ ((off + i) >> 16));
}

// "2026-09-30T07:21:14Z  (local 2026-09-30 15:21:14 UTC+08:00)": ISO 8601 UTC,
// plus local time with the UTC offset in effect at that moment (DST-aware).
static std::wstring FormatUtcAndLocal(FILETIME ft) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) GetSystemTimeAsFileTime(&ft);
    SYSTEMTIME u, l;
    FileTimeToSystemTime(&ft, &u);
    if (!SystemTimeToTzSpecificLocalTime(nullptr, &u, &l)) l = u;
    FILETIME lf;
    SystemTimeToFileTime(&l, &lf);
    ULARGE_INTEGER a, b;
    a.LowPart = ft.dwLowDateTime; a.HighPart = ft.dwHighDateTime;
    b.LowPart = lf.dwLowDateTime; b.HighPart = lf.dwHighDateTime;
    // Round to whole minutes: SYSTEMTIME drops sub-millisecond ticks, so the raw
    // difference is a hair short of the real offset (e.g. 7:59:59.9999).
    long long diff = (long long)b.QuadPart - (long long)a.QuadPart;   // 100 ns units
    long long offMin = (diff + (diff >= 0 ? 300000000LL : -300000000LL)) / 600000000LL;
    long long absMin = offMin < 0 ? -offMin : offMin;
    wchar_t buf[96];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                 L"%04u-%02u-%02uT%02u:%02u:%02uZ  (local %04u-%02u-%02u %02u:%02u:%02u UTC%c%02lld:%02lld)",
                 u.wYear, u.wMonth, u.wDay, u.wHour, u.wMinute, u.wSecond,
                 l.wYear, l.wMonth, l.wDay, l.wHour, l.wMinute, l.wSecond,
                 offMin < 0 ? L'-' : L'+', absMin / 60, absMin % 60);
    return buf;
}

static RunLog g_log;

// Tell the UI which phase the worker is in (wParam = CapturePhase) and how
// many bytes that phase expects in total (lParam, 0 = unknown); log it too.
static void PostPhase(CapturePhase phase, UINT64 totalBytes) {
    static const wchar_t* kNames[] = { L"Capturing memory image", L"Hashing image (SHA-256)",
                                       L"Splitting image into parts", L"Collecting system files" };
    g_log.Line(std::wstring(L"Phase: ") + kNames[(int)phase] +
               (totalBytes ? L" (" + std::to_wstring(totalBytes) + L" bytes expected)" : L""));
    PostMessageW(g_hwnd, WM_APP_PHASE, (WPARAM)phase, (LPARAM)totalBytes);
}

// "Case:" / "Examiner:" / "Notes:" lines for the .meta sidecars and the run
// log - only the details that were filled in (empty string when none were).
static std::wstring CaseDetailsLines() {
    std::wstring s;
    if (!g_caseNumber.empty())   s += L"Case:        " + g_caseNumber + L"\n";
    if (!g_caseExaminer.empty()) s += L"Examiner:    " + g_caseExaminer + L"\n";
    if (!g_caseNotes.empty())    s += L"Notes:       " + g_caseNotes + L"\n";
    return s;
}

// A whole-image hash (res->sha256) as shown in the .meta sidecar
// and the completion dialog.
static std::wstring HashText(const CaptureResult* res, const std::string& hash) {
    if (!hash.empty()) return Utf8ToWide(hash);
    if (res->cancelled || res->hashStopped) return L"not computed (stopped by user)";
    return L"not computed";
}

// Write the .meta sidecar for a completed capture. Used by both the driverless
// and WinPmem-driver paths so every RAMstain image gets the same documentation.
static void WriteMetaSidecar(CaptureResult* res, bool selftest) {
    if (!res->ok) return;
    std::wstring hostName  = GetComputerName();
    std::wstring osVersion = GetOsVersionString();
    std::wstring kernelVer = GetKernelVersionString();

    std::wstring metaPath = res->path;
    StripExtensionInPlace(metaPath);
    metaPath += L".meta";
    std::wstring imageLine = res->parts.empty()
        ? res->path
        : res->parts.front().path + L" ... " + res->parts.back().path +
          L" (" + std::to_wstring(res->parts.size()) + L" parts)";
    std::wstring partsBlock;
    if (!res->parts.empty()) {
        std::wstring base = res->path;
        StripExtensionInPlace(base);
        size_t sl = base.find_last_of(L"\\/");
        std::wstring baseName = (sl == std::wstring::npos) ? base : base.substr(sl + 1);
        std::wstring origName = res->path.substr(res->path.find_last_of(L"\\/") + 1);
        partsBlock =
            L"Split:       " + std::to_wstring(res->parts.size()) + L" parts of up to " +
            std::to_wstring(res->parts.front().bytes) + L" bytes. The hashes above are of "
            L"the whole image (all parts joined in order).\n"
            L"Rejoin:      copy /b " + baseName + L".001 + " + baseName + L".002 + ... " +
            origName + L"\n";
        for (size_t i = 0; i < res->parts.size(); ++i) {
            const SplitPart& p = res->parts[i];
            wchar_t num[16];
            _snwprintf_s(num, _countof(num), _TRUNCATE, L"%03u", (unsigned)(i + 1));
            auto h = [](const std::string& s) {
                return s.empty() ? std::wstring(L"not computed") : Utf8ToWide(s);
            };
            partsBlock += L"Part " + std::wstring(num) + L":    " +
                          p.path.substr(p.path.find_last_of(L"\\/") + 1) + L"  " +
                          std::to_wstring(p.bytes) + L" bytes\n" +
                          L"  SHA-256:   " + h(p.sha256) + L"\n";
        }
    }
    if (!res->splitError.empty())
        partsBlock += L"Note:        Split incomplete - " + res->splitError + L"\n";

    std::wstring meta =
        L"RAMstain capture metadata\n"
        L"=========================\n" +
        CaseDetailsLines() +
        L"Image:       " + imageLine + L"\n" +
        L"Host:        " + hostName + L"\n" +
        L"OS:          " + osVersion + L"\n" +
        L"Kernel:      " + kernelVer + L"\n" +
        L"Started:     " + FormatUtcAndLocal(res->startUtc) + L"\n" +
        L"Finished:    " + FormatUtcAndLocal(res->endUtc) + L"\n" +
        L"Size:        " + std::to_wstring(res->bytesWritten) + L" bytes\n" +
        L"Pages:       " + std::to_wstring(res->pagesWritten) + L" x 4096 bytes\n" +
        L"SHA-256:     " + HashText(res, res->sha256) + L"\n" +
        L"Tool:        RAMstain " + kVersionStr + L"\n" +
        L"Method:      " + (selftest
            ? std::wstring(L"SELF-TEST synthetic source (not a memory capture)\n")
            : (res->method.empty()
                ? std::wstring(L"Driverless OpenProcess(PID -1) + ReadProcessMemory (experimental)\n")
                : (res->method + L"\n"))) +
        (res->cancelled ? L"Note:        Capture stopped by user (partial image, not hashed)\n" : L"") +
        (res->hashStopped ? L"Note:        Image complete; hashes skipped (stopped by user during hashing)\n" : L"") +
        partsBlock;
    std::string metaUtf8 = WideToUtf8(meta);
    HANDLE hm = CreateFileW(metaPath.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hm != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        if (WriteFile(hm, metaUtf8.data(), (DWORD)metaUtf8.size(), &wr, nullptr))
            res->metaPath = metaPath;
        CloseHandle(hm);
    }
}

// <base>.001, <base>.002, ... (the FTK / X-Ways / Autopsy split-raw convention).
static std::wstring PartPath(const std::wstring& base, UINT64 k) {
    wchar_t num[24];
    _snwprintf_s(num, _countof(num), _TRUNCATE, L".%03llu", (unsigned long long)k);
    return base + num;
}

// Split the finished image res->path into g_splitBytes-sized parts, in place.
//
// Works backwards from the end: copy the last slice into its part file, flush
// it, then truncate the original to drop that slice; repeat; finally rename
// what is left of the original to <base>.001. So the extra disk space needed
// at any moment is one part, not a second copy of the whole image, and the
// data is always complete on disk (a slice is removed from the original only
// after its part file is flushed). Stop is ignored during this phase - an
// interrupted split would leave the evidence scattered across files.
static void SplitImage(CaptureResult* res) {
    const UINT64 ps = g_splitBytes;
    if (ps == 0 || !res->ok) return;

    HANDLE orig = CreateFileW(res->path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (orig == INVALID_HANDLE_VALUE) {
        res->splitError = L"could not open the image to split it (error " +
                          std::to_wstring(GetLastError()) + L"); it was left as one file.";
        return;
    }
    LARGE_INTEGER sz = {0};
    GetFileSizeEx(orig, &sz);
    const UINT64 total = (UINT64)sz.QuadPart;
    if (total <= ps) { CloseHandle(orig); return; }   // fits in one part: nothing to do

    std::wstring base = res->path;
    StripExtensionInPlace(base);
    const UINT64 n = (total + ps - 1) / ps;
    for (UINT64 k = 1; k <= n; ++k) {
        if (_wcsicmp(PartPath(base, k).c_str(), res->path.c_str()) == 0) {
            CloseHandle(orig);
            res->splitError = L"the image file name clashes with the part names (" +
                              PartPath(base, k) + L"); it was left as one file.";
            return;
        }
    }
    // Remove parts left over from an earlier capture with the same name (the
    // user already confirmed overwriting it), so no stale .00N survives.
    for (UINT64 k = 1; DeleteFileW(PartPath(base, k).c_str()) ||
                       GetLastError() != ERROR_FILE_NOT_FOUND; ++k) {}

    PostPhase(CapturePhase::Splitting, total - ps);
    PostMessageW(g_hwnd, WM_APP_PROGRESS, 0, 0);

    std::vector<SplitPart> parts((size_t)n);
    std::vector<BYTE> buf(4 * 1024 * 1024);
    UINT64 end = total, moved = 0, lastPosted = 0;
    for (UINT64 k = n; k >= 2; --k) {
        const UINT64 off = (k - 1) * ps;
        const UINT64 len = end - off;
        std::wstring part = PartPath(base, k);
        HANDLE hp = CreateFileW(part.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        bool ok = hp != INVALID_HANDLE_VALUE;
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)off;
        ok = ok && SetFilePointerEx(orig, li, nullptr, FILE_BEGIN);
        for (UINT64 left = len; ok && left > 0;) {
            DWORD want = (DWORD)min((UINT64)buf.size(), left), rd = 0, wr = 0;
            ok = ReadFile(orig, buf.data(), want, &rd, nullptr) && rd == want &&
                 WriteFile(hp, buf.data(), rd, &wr, nullptr) && wr == rd;
            left -= rd; moved += rd;
            if (moved - lastPosted >= 64ull * 1024 * 1024) {
                lastPosted = moved;
                PostMessageW(g_hwnd, WM_APP_PROGRESS,
                             (WPARAM)(int)((double)moved / (double)(total - ps) * 100.0),
                             (LPARAM)moved);
            }
        }
        ok = ok && FlushFileBuffers(hp);          // part is durable before we cut
        DWORD e = ok ? 0 : GetLastError();
        if (hp != INVALID_HANDLE_VALUE) CloseHandle(hp);
        ok = ok && SetFilePointerEx(orig, li, nullptr, FILE_BEGIN) && SetEndOfFile(orig);
        if (!ok) {
            if (!e) e = GetLastError();
            // The original still holds this slice (it is only cut after the part
            // is flushed), so the incomplete or duplicate part file can go.
            DeleteFileW(part.c_str());
            CloseHandle(orig);
            res->splitError = L"could not write part " + std::to_wstring(k) + L" (error " +
                              std::to_wstring(e) + (e == ERROR_DISK_FULL ? L", disk full" : L"") +
                              L"). Parts " + std::to_wstring(k + 1) + L"-" + std::to_wstring(n) +
                              L" were written; the rest of the image is still in " + res->path +
                              L". No data was lost.";
            if (k == n) res->splitError = L"could not write the last part (error " +
                              std::to_wstring(e) + (e == ERROR_DISK_FULL ? L", disk full" : L"") +
                              L"); the image was left as one file. No data was lost.";
            return;
        }
        parts[(size_t)(k - 1)] = SplitPart{ part, len, "" };
        end = off;
    }
    CloseHandle(orig);

    std::wstring first = PartPath(base, 1);
    if (!MoveFileExW(res->path.c_str(), first.c_str(), MOVEFILE_WRITE_THROUGH)) {
        res->splitError = L"parts 2-" + std::to_wstring(n) + L" were written, but the first "
                          L"part could not be renamed (error " + std::to_wstring(GetLastError()) +
                          L"); it is still named " + res->path + L". No data was lost.";
        return;
    }
    parts[0] = SplitPart{ first, ps, "" };
    if (res->partSha256.size() == parts.size())
        for (size_t i = 0; i < parts.size(); ++i) {
            parts[i].sha256 = res->partSha256[i];
        }
    res->parts = std::move(parts);
}

// Last step of every capture: split (if requested), then write the .meta sidecar.
static void FinishImage(CaptureResult* res, bool selftest) {
    SplitImage(res);
    if (!res->parts.empty())
        g_log.Line(L"Split into " + std::to_wstring(res->parts.size()) + L" parts: " +
                   res->parts.front().path + L" ... " + res->parts.back().path);
    if (!res->splitError.empty())
        g_log.Line(L"Split incomplete: " + res->splitError);
    WriteMetaSidecar(res, selftest);
    if (!res->metaPath.empty())
        g_log.Line(L"Metadata sidecar written: " + res->metaPath);
}

static void RunCapture(CaptureResult* res, bool selftest) {
    const size_t kPageSize = 4096;
    const size_t kChunkBytes = 2 * 1024 * 1024; // 2 MiB read buffer
    UINT64 neededBytes = selftest
                             ? (512u * 1024 * 1024) // 512 MiB synthetic in self-test
                             : (UINT64)(GetTotalRamGB() * 1024.0 * 1024.0 * 1024.0);

    HANDLE hPhys = nullptr;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    auto cleanup = [&]() {
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
        if (hPhys) CloseHandle(hPhys);
    };

    // Enable SeDebugPrivilege (harmless if already held / already elevated).
    EnableSeDebugPrivilege();

    // Open physical memory (PID -1). Skipped in self-test (synthetic source).
    if (!selftest) {
        hPhys = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                            FALSE, (DWORD)-1);
        if (!hPhys) {
            UINT code = GetLastError();
            res->errCode = code;
            std::wstring os = GetOsVersionString();
            if (code == ERROR_INVALID_PARAMETER) {
                res->error =
                    L"The experimental driverless method is not available on this system.\n"
                    L"OpenProcess(PID -1) failed with error 87 (ERROR_INVALID_PARAMETER) "
                    L"on " + os + L".\n\n"
                    L"Error 87 is what Windows returns for any process ID that does not "
                    L"exist; PID -1 is not a documented physical-memory handle.\n\n"
                    L"Use the WinPmem driver instead: tick 'Use WinPmem driver' "
                    L"(the imager is built into RAMstain).";
            } else if (code == ERROR_ACCESS_DENIED) {
                res->error =
                    L"Physical-memory access denied (error " +
                    std::to_wstring(code) + L").\n\n"
                    L"RAMstain must run as Administrator.";
            } else {
                res->error =
                    L"OpenProcess(physical memory) failed - error " +
                    std::to_wstring(code) + L".\n\n"
                    L"RAMstain must run as Administrator with no security "
                    L"software blocking physical memory access.";
            }
            cleanup();
            return;
        }
    }

    // Create output image.
    hFile = CreateFileW(res->path.c_str(), GENERIC_WRITE, 0, nullptr,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        UINT code = GetLastError();
        std::wstring hint;
        if (code == ERROR_DISK_FULL) hint = L" (disk full)";
        else if (code == ERROR_PATH_NOT_FOUND) hint = L" (path does not exist)";
        else if (code == ERROR_ACCESS_DENIED) hint = L" (access denied)";
        res->errCode = code;
        res->error = L"Cannot create output file:\n" + res->path + L"\n\nError " +
                     std::to_wstring(code) + hint;
        cleanup();
        return;
    }

    // Metadata is written via the shared sidecar writer (WriteMetaSidecar).

    // SHA-256 (plus per-part hashes if the image will be split) on background
    // threads while streaming.
    HashPipeline hash(kChunkBytes, g_splitBytes);
    PostPhase(CapturePhase::Capturing, neededBytes);

    UINT64 offset = 0;
    bool   anyWritten = false;
    bool   aborted = false;

    while (true) {
        if (g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) {
            res->cancelled = true;
            break;
        }
        BYTE* buf = hash.Acquire();
        SIZE_T got = 0;
        if (selftest) {
            got = (SIZE_T)kChunkBytes;
            FillSynthetic(buf, kChunkBytes, offset);
        } else if (!ReadProcessMemory(hPhys, (LPCVOID)(SIZE_T)offset, buf,
                                      kChunkBytes, &got) || got == 0) {
            // First read failed -> real error. Otherwise end of usable range.
            if (anyWritten) break;
            UINT code = GetLastError();
            res->errCode = code;
            res->error = L"ReadProcessMemory failed on first page - error " +
                         std::to_wstring(code) +
                         L".\n\nA security product or system policy may be "
                         L"blocking physical memory reads.";
            aborted = true;
            break;
        }
        DWORD written = 0;
        if (!WriteFile(hFile, buf, (DWORD)got, &written, nullptr) ||
            written != (DWORD)got) {
            UINT code = GetLastError();
            res->errCode = code;
            res->error = L"WriteFile failed - error " + std::to_wstring(code) +
                         (code == ERROR_DISK_FULL ? L" (disk full)" : L"") +
                         L".\nCapture aborted.";
            aborted = true;
            break;
        }
        hash.Submit(got);
        anyWritten = true;
        offset += got;
        res->bytesWritten = offset;
        res->pagesWritten = offset / kPageSize;

        int pct = (int)((double)offset / (double)neededBytes * 100.0);
        if (pct > 100) pct = 100;
        PostMessageW(g_hwnd, WM_APP_PROGRESS, (WPARAM)pct, (LPARAM)offset);

        if (offset >= neededBytes) break;
    }

    GetSystemTimeAsFileTime(&res->endUtc);   // image data complete
    cleanup();

    if (aborted) return;
    res->ok = res->bytesWritten > 0;
    // A user-stopped (partial) image gets no hashes, same as the driver path.
    if (!res->cancelled) {
        res->sha256 = hash.Finish(&res->partSha256);
        g_log.Line(L"Image SHA-256: " + Utf8ToWide(res->sha256) + L" (" +
                   std::to_wstring(res->bytesWritten) + L" bytes)");
    }

    // Split if requested, then write the .meta sidecar (shared with the driver path).
    FinishImage(res, selftest);
}

// ---------------------------------------------------------------------------
//  WinPmem driver capture (the default method).
//
//  Runs the signed Velocidex WinPmem imager, which loads its own signed kernel
//  driver, writes the .raw image, then unloads it. We compute SHA-256 over the
//  resulting file and write the same .meta sidecar as the driverless path.
//
//  The imager is embedded in RAMstain.exe (IDR_WINPMEM, third_party/winpmem/).
//  It is written to disk only when a driver-mode capture needs it, into
//  %TEMP%\RAMstain-<pid>\ - a folder whose ACL allows only Administrators and
//  SYSTEM, so a non-elevated process cannot swap the file before we run it
//  elevated - and that folder is deleted when RAMstain exits. Folders left by
//  a crashed instance are swept at the next start.
//
//  An external imager can still be used instead of the embedded one:
//    1. --driver <path> on the command line
//    2. %RAMSTAIN_WINPMEM% environment variable (a path to the exe)
// ---------------------------------------------------------------------------
static std::wstring g_dropDir;      // extraction folder (empty = nothing extracted)
static std::wstring g_dropImager;   // extracted imager path (reused for later captures)

// External imager override, if one was given (--driver or RAMSTAIN_WINPMEM).
static bool GetImagerOverride(std::wstring& path) {
    if (!g_driverPath.empty()) { path = g_driverPath; return true; }
    wchar_t env[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"RAMSTAIN_WINPMEM", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH) { path = env; return true; }
    return false;
}

static bool HasEmbeddedImager() {
    return FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_WINPMEM), RT_RCDATA) != nullptr;
}

// UI pre-check before a driver-mode capture: empty string = an imager is
// available, otherwise a user-facing explanation.
static std::wstring CheckImagerAvailable() {
    std::wstring ovr;
    if (GetImagerOverride(ovr)) {
        if (GetFileAttributesW(ovr.c_str()) != INVALID_FILE_ATTRIBUTES) return L"";
        return L"The external WinPmem imager given with --driver or the "
               L"RAMSTAIN_WINPMEM environment variable was not found:\n" + ovr +
               L"\n\nRemove the override to use the imager built into RAMstain.";
    }
    if (HasEmbeddedImager()) return L"";
    return L"This RAMstain build does not contain the embedded WinPmem imager.\n\n"
           L"Pass an external imager:  RAMstain.exe --driver C:\\path\\winpmem.exe";
}

static std::wstring TempDir() {
    wchar_t buf[MAX_PATH + 1] = L"";
    DWORD n = GetTempPathW(MAX_PATH + 1, buf);
    std::wstring t = (n > 0 && n <= MAX_PATH) ? std::wstring(buf, n) : L"C:\\Windows\\Temp\\";
    if (t.back() != L'\\') t.push_back(L'\\');
    return t;
}

static std::wstring DropDirForPid(DWORD pid) {
    return TempDir() + L"RAMstain-" + std::to_wstring(pid);
}

// Delete every file in `dir`, then the folder. Retries briefly because the
// imager may have exited only moments ago and still hold its image mapped.
static bool DeleteDropDir(const std::wstring& dir) {
    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring f = dir + L"\\" + fd.cFileName;
            SetFileAttributesW(f.c_str(), FILE_ATTRIBUTE_NORMAL);
            for (int i = 0; i < 20 && !DeleteFileW(f.c_str()) &&
                            GetLastError() != ERROR_FILE_NOT_FOUND; ++i)
                Sleep(100);
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
    for (int i = 0; i < 20; ++i) {
        if (RemoveDirectoryW(dir.c_str())) return true;
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return true;
        Sleep(100);
    }
    return false;
}

static bool IsProcessAlive(DWORD pid) {
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return GetLastError() == ERROR_ACCESS_DENIED; // exists, just not ours
    bool alive = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
    CloseHandle(h);
    return alive;
}

// Remove %TEMP%\RAMstain-<pid> folders left behind by instances that are no
// longer running (e.g. RAMstain crashed or was killed mid-capture).
static void SweepStaleDropDirs() {
    std::wstring tmp = TempDir();
    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW((tmp + L"RAMstain-*").c_str(), &fd);
    if (hf == INVALID_HANDLE_VALUE) return;
    DWORD self = GetCurrentProcessId();
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        const wchar_t* digits = fd.cFileName + 9;   // after "RAMstain-"
        if (!*digits || wcsspn(digits, L"0123456789") != wcslen(digits)) continue;
        DWORD pid = (DWORD)wcstoul(digits, nullptr, 10);
        if (pid == self || IsProcessAlive(pid)) continue;
        DeleteDropDir(tmp + fd.cFileName);
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
}

// Called when RAMstain exits: remove the extracted imager and its folder.
static void CleanupDroppedImager() {
    if (!g_dropDir.empty()) DeleteDropDir(g_dropDir);
    g_dropDir.clear();
    g_dropImager.clear();
}

// Write the embedded imager into the protected drop folder (once per run).
static std::wstring ExtractEmbeddedImager(std::wstring& err) {
    if (!g_dropImager.empty() &&
        GetFileAttributesW(g_dropImager.c_str()) != INVALID_FILE_ATTRIBUTES)
        return g_dropImager;

    HRSRC hr = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_WINPMEM), RT_RCDATA);
    HGLOBAL hg = hr ? LoadResource(nullptr, hr) : nullptr;
    const void* data = hg ? LockResource(hg) : nullptr;
    DWORD size = hr ? SizeofResource(nullptr, hr) : 0;
    if (!data || size == 0) {
        err = L"The embedded WinPmem imager could not be loaded from RAMstain.exe.";
        return L"";
    }

    std::wstring dir = DropDirForPid(GetCurrentProcessId());
    if (GetFileAttributesW(dir.c_str()) != INVALID_FILE_ATTRIBUTES)
        DeleteDropDir(dir);   // stale folder from an earlier process with our PID

    // Protected DACL: full control for Administrators and SYSTEM only, no
    // inheritance from %TEMP% (the "P" flag). Files created inside inherit it.
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)", SDDL_REVISION_1, &psd, nullptr)) {
        err = L"Could not build the security descriptor for the imager folder (error " +
              std::to_wstring(GetLastError()) + L").";
        return L"";
    }
    SECURITY_ATTRIBUTES sa = { sizeof(sa), psd, FALSE };
    BOOL made = CreateDirectoryW(dir.c_str(), &sa);
    DWORD mkErr = GetLastError();
    LocalFree(psd);
    if (!made) {
        err = L"Could not create the imager folder (error " + std::to_wstring(mkErr) +
              L"):\n" + dir;
        return L"";
    }
    g_dropDir = dir;   // from here on, exit cleanup removes it

    std::wstring file = dir + L"\\winpmem_x64.exe";
    HANDLE h = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = L"Could not write the embedded WinPmem imager (error " +
              std::to_wstring(GetLastError()) + L"):\n" + file;
        return L"";
    }
    DWORD wr = 0;
    BOOL ok = WriteFile(h, data, size, &wr, nullptr) && wr == size;
    DWORD wErr = GetLastError();
    CloseHandle(h);
    if (!ok) {
        DeleteFileW(file.c_str());
        err = L"Could not write the embedded WinPmem imager (error " +
              std::to_wstring(wErr) + L"):\n" + file +
              L"\n\nAn antivirus product may have blocked or removed it.";
        return L"";
    }
    g_dropImager = file;
    return file;
}

// The imager to run for this capture: the external override if one was given,
// otherwise the embedded one (extracted on first use).
static std::wstring ResolveImager(bool& embedded, std::wstring& err) {
    std::wstring ovr;
    if (GetImagerOverride(ovr)) {
        embedded = false;
        if (GetFileAttributesW(ovr.c_str()) != INVALID_FILE_ATTRIBUTES) return ovr;
        err = L"External WinPmem imager not found:\n" + ovr;
        return L"";
    }
    embedded = true;
    return ExtractEmbeddedImager(err);
}

static DWORD WaitForAnyStop(DWORD, DWORD ms) {
    if (g_stopEvent)
        return WaitForSingleObject(g_stopEvent, ms);
    return WAIT_TIMEOUT;
}

// Current size of a file (0 if it does not exist). Opens with attribute-only
// access and full sharing so it works while another process (the imager) has
// the file open for writing; a GENERIC_READ open would hit a sharing violation.
// Files the kernel holds with no sharing at all (pagefile.sys, hiberfil.sys)
// cannot be opened even like that, so fall back to the directory entry.
static UINT64 GetFileBytes(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        WIN32_FIND_DATAW fd;
        HANDLE hf = FindFirstFileW(path.c_str(), &fd);
        if (hf == INVALID_HANDLE_VALUE) return 0;
        FindClose(hf);
        return ((UINT64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
    }
    LARGE_INTEGER sz = {0};
    BOOL ok = GetFileSizeEx(h, &sz);
    CloseHandle(h);
    return ok ? (UINT64)sz.QuadPart : 0;
}

// Compute the SHA-256 of a completed image in one pass into res->sha256
// (no-op if the file is missing). Only called for images that were
// not stopped mid-capture. If the user presses Stop while hashing, the hashes
// are abandoned (left empty, res->hashStopped set) - a hash cut short must
// never be recorded.
static void HashFile(CaptureResult* res) {
    HANDLE hf = CreateFileW(res->path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz = {0};
    GetFileSizeEx(hf, &sz);
    UINT64 total = (UINT64)sz.QuadPart;
    PostPhase(CapturePhase::Hashing, total);
    PostMessageW(g_hwnd, WM_APP_PROGRESS, 0, 0);

    // Read here while the SHA-256 (and per-part hashes) run on background
    // threads, so reading the next block overlaps hashing the previous ones.
    const DWORD kBlock = 8 * 1024 * 1024;
    HashPipeline hash(kBlock, g_splitBytes);
    UINT64 done = 0, lastPosted = 0;
    for (;;) {
        if (g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) {
            res->hashStopped = true;
            g_log.Line(L"Hashing stopped by user after " + std::to_wstring(done) +
                       L" bytes; no hash recorded.");
            CloseHandle(hf);
            return;
        }
        BYTE* buf = hash.Acquire();
        DWORD rd = 0;
        if (!ReadFile(hf, buf, kBlock, &rd, nullptr)) {
            g_log.Line(L"Hashing failed: read error " + std::to_wstring(GetLastError()) +
                       L" at offset " + std::to_wstring(done) + L"; no hash recorded.");
            CloseHandle(hf);                 // read error: no hash rather than a
            return;                          // hash of a truncated image
        }
        if (rd == 0) break;
        hash.Submit(rd);
        done += rd;
        if (done - lastPosted >= 64ull * 1024 * 1024) {  // ~every 64 MiB
            lastPosted = done;
            int pct = total ? (int)((double)done / (double)total * 100.0) : 0;
            PostMessageW(g_hwnd, WM_APP_PROGRESS, (WPARAM)(pct > 100 ? 100 : pct), (LPARAM)done);
        }
    }
    CloseHandle(hf);
    res->sha256 = hash.Finish(&res->partSha256);
    g_log.Line(L"Image SHA-256: " + Utf8ToWide(res->sha256) + L" (" + std::to_wstring(done) + L" bytes)");
}

// ---------------------------------------------------------------------------
//  System file collection (pagefile.sys / hiberfil.sys)
//
//  These are held open by the kernel with no sharing for the whole session,
//  so a normal open fails even for an Administrator; they are read raw from
//  the NTFS volume instead (see MapLockedFile) - no kernel driver is needed.
//  Each one is copied in full to a file next to the memory image, hashing in
//  a single pass. Independent of the memory
//  capture itself, so a pagefile/hibernation file is still collected even if
//  the memory image fails (the .meta sidecar says so).
// ---------------------------------------------------------------------------

// Volume root of the system volume, e.g. "C:\\". GetWindowsDirectoryW may
// point inside a subfolder (C:\Windows, C:\WIN, D:\Win, ...), so only the
// drive prefix is the volume root that holds pagefile.sys / hiberfil.sys.
static std::wstring GetSystemVolume() {
    wchar_t sysroot[MAX_PATH] = L"";
    DWORD n = GetWindowsDirectoryW(sysroot, MAX_PATH);
    if (n == 0 || n >= MAX_PATH || n < 3) return L"";
    return std::wstring(sysroot, 3);   // "C:\" + the backslash
}

// Full paths of every pagefile the system is using, from the registry
// (HKLM\...\Session Manager\Memory Management\ExistingPageFiles, a
// REG_MULTI_SZ of NT paths such as "\??\C:\pagefile.sys").
static std::vector<std::wstring> GetPagefilePaths() {
    std::vector<std::wstring> out;
    wchar_t value[2048] = L"";
    DWORD cb = sizeof(value) - sizeof(wchar_t);   // keep a final NUL for the walk below
    LSTATUS st = RegGetValueW(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
                              L"ExistingPageFiles", RRF_RT_REG_MULTI_SZ, nullptr, value, &cb);
    if (st == ERROR_SUCCESS) {
        for (const wchar_t* p = value; *p; p += wcslen(p) + 1) {
            std::wstring s = p;
            if (s.compare(0, 4, L"\\??\\") == 0) s.erase(0, 4);   // NT prefix -> Win32 path
            TrimRight(s);
            if (s.size() > 3 && s[1] == L':') out.push_back(s);
        }
    }
    // Not listed (value absent) => the default <system volume>\pagefile.sys.
    if (out.empty()) {
        std::wstring sv = GetSystemVolume();
        if (!sv.empty()) out.push_back(sv + L"pagefile.sys");
    }
    return out;
}

// Where the hibernation file is. In standard Windows it is always on the
// boot/system volume (the volume that holds Windows); there is no documented
// per-volume override, so the system volume is the authoritative location.
static std::wstring GetHiberfilPath() {
    std::wstring sv = GetSystemVolume();
    return sv.empty() ? std::wstring() : sv + L"hiberfil.sys";
}

// Candidate locations of a system file (the first that exists is collected).
// swapfile.sys (the swap file for Store/UWP apps) sits next to the pagefile
// on the system volume.
static std::vector<std::wstring> SysFileSources(SysKind k) {
    if (k == SysKind::Pagefile) return GetPagefilePaths();
    std::wstring sv = GetSystemVolume();
    if (sv.empty()) return {};
    return { k == SysKind::Hiberfil ? GetHiberfilPath() : sv + L"swapfile.sys" };
}

static bool& SysWanted(SysKind k) {
    return k == SysKind::Pagefile ? g_collectPagefile
         : k == SysKind::Hiberfil ? g_collectHiberfil : g_collectSwapfile;
}

// Reads the directory entry rather than the file: GetFileAttributesW opens the
// file, which fails with a sharing violation on pagefile.sys / hiberfil.sys.
static bool FilePresent(const std::wstring& p) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(p.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    FindClose(h);
    return !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
}


// The .meta sidecar for one requested system file (written on every outcome -
// success, partial, or "not found" - so the record exists either way).
// metaPath is passed explicitly; the "Collected:" line is empty->"(not collected)".
// memNote describes the memory image state at collection time.
static void WriteSysFileMeta(const SysFileCapture& sf, const std::wstring& metaPath,
                             const wchar_t* memNote) {
    if (metaPath.empty()) return;
    std::wstring host = GetComputerName();
    std::wstring os = GetOsVersionString();
    std::wstring label = std::wstring(SysName(sf.kind)) + L".sys";
    auto ht = [](const std::string& h) { return h.empty() ? std::wstring(L"not computed") : Utf8ToWide(h); };
    std::wstring m;
    m += L"RAMstain system file metadata\n";
    m += L"=============================\n";
    m += CaseDetailsLines();
    m += L"File:        ";  m += label;  m += L"\n";
    m += L"Source:      ";  m += (sf.source.empty() ? L"not found on this system" : sf.source);  m += L"\n";
    m += L"Collected:   ";  m += (sf.path.empty() ? L"(not collected)" : sf.path);  m += L"\n";
    m += L"Host:        ";  m += host;  m += L"\n";
    m += L"OS:          ";  m += os;  m += L"\n";
    m += L"Started:     ";  m += FormatUtcAndLocal(sf.startUtc);  m += L"\n";
    m += L"Finished:    ";  m += FormatUtcAndLocal(sf.endUtc);  m += L"\n";
    m += L"Size:        ";  m += std::to_wstring(sf.bytes);  m += L" bytes\n";
    m += L"SHA-256:     ";  m += ht(sf.sha256);  m += L"\n";
    if (!sf.method.empty()) { m += L"Method:      "; m += sf.method; m += L"\n"; }
    m += L"Note:        ";  m += memNote;  m += L"\n";
    if (!sf.error.empty()) { m += L"Note:        "; m += sf.error; m += L"\n"; }
    std::string u = WideToUtf8(m);
    HANDLE h = CreateFileW(metaPath.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        WriteFile(h, u.data(), (DWORD)u.size(), &wr, nullptr);
        CloseHandle(h);
    }
}

// Copy one source file to dst, hashing in the same pass. Returns true when the
// whole file was copied. On a partial/failed copy, dst is removed and
// sf.error is set; on success sf.path/sha256/bytes/timestamps are filled.
// A file the OS holds open without sharing (always the case for a live
// pagefile.sys / hiberfil.sys) is read raw from the NTFS volume instead.
static bool CopySystemFile(const std::wstring& src, const std::wstring& dst, SysFileCapture& sf) {
    sf.source = src;
    HANDLE hIn = CreateFileW(src.c_str(), GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    RawFileMap map;
    if (hIn != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz = {0};
        GetFileSizeEx(hIn, &sz);
        sf.bytes = (UINT64)sz.QuadPart;
        sf.method = L"File copy (Administrator)";
    } else {
        DWORD code = GetLastError();
        if (code != ERROR_SHARING_VIOLATION) {
            sf.error = L"could not open " + src + L" (error " + std::to_wstring(code) + L").";
            return false;
        }
        std::wstring why;
        if (!MapLockedFile(src, map, why)) {
            sf.error = L"file is locked by Windows and raw reading failed: " + why + L".";
            return false;
        }
        sf.bytes = map.size;
        sf.method = L"Raw NTFS read from the volume (file locked by Windows; live contents)";
    }
    RawFileReader raw(map);

    DeleteFileW(dst.c_str());  // replace a stale copy; overwrite was confirmed
    HANDLE hOut = CreateFileW(dst.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) {
        if (hIn != INVALID_HANDLE_VALUE) CloseHandle(hIn);
        sf.error = L"could not create " + dst + L" (error " + std::to_wstring(GetLastError()) + L").";
        return false;
    }

    // Hash on a background thread while the next block is read and written.
    // (8 MiB is a multiple of any NTFS cluster size, as the raw reader needs.)
    const DWORD kBlock = 8 * 1024 * 1024;
    HashPipeline hash(kBlock, 0);
    UINT64 done = 0, lastPosted = 0;
    double totalDouble = sf.bytes > 0 ? (double)sf.bytes : 1.0;
    bool ok = true;
    GetSystemTimeAsFileTime(&sf.startUtc);
    while (done < sf.bytes) {
        if (g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) { ok = false; break; }
        BYTE* buf = hash.Acquire();
        DWORD rd = 0;
        bool readOk = (hIn != INVALID_HANDLE_VALUE)
            ? ReadFile(hIn, buf, (DWORD)min((UINT64)kBlock, sf.bytes - done), &rd, nullptr) != FALSE
            : raw.Read(buf, kBlock, rd);
        if (!readOk) {
            ok = false;
            sf.error = L"read failed at offset " + std::to_wstring(done) + L" (error " +
                       std::to_wstring(GetLastError()) + L"); partial copy discarded.";
            break;
        }
        if (rd == 0) {
            ok = false;
            sf.error = L"source file shrank while being read (copied " + std::to_wstring(done) +
                       L" of " + std::to_wstring(sf.bytes) + L" bytes); partial copy discarded.";
            break;
        }
        if (!WriteFile(hOut, buf, rd, nullptr, nullptr)) {
            ok = false;
            sf.error = L"write failed (error " + std::to_wstring(GetLastError()) +
                       L"); partial copy discarded.";
            break;
        }
        hash.Submit(rd);
        done += rd;
        if (done - lastPosted >= 64ull * 1024 * 1024) {
            lastPosted = done;
            PostMessageW(g_hwnd, WM_APP_PROGRESS,
                         (WPARAM)(int)((double)done / totalDouble * 100.0),
                         (LPARAM)done);
        }
    }
    GetSystemTimeAsFileTime(&sf.endUtc);
    sf.bytes = done;
    if (ok) {
        sf.sha256 = hash.Finish();
        sf.path = dst;
    } else if (sf.error.empty()) {
        sf.error = L"collection stopped by user (partial copy discarded).";
    }
    if (ok) FlushFileBuffers(hOut);
    CloseHandle(hOut);
    if (!ok) DeleteFileW(dst.c_str());  // after the handle is closed, or the OS refuses
    if (hIn != INVALID_HANDLE_VALUE) CloseHandle(hIn);
    return ok;
}

// Collect one requested system file into res->sysfiles. A .meta sidecar is
// written for every outcome so the record always exists.
static void CollectSystemFile(CaptureResult* res, SysKind kind) {
    SysFileCapture sf;
    sf.kind = kind;
    std::wstring base = res->path;
    StripExtensionInPlace(base);
    std::wstring dst = base + L"__" + SysName(kind) + L".raw";

    // Memory-image state at collection time, for the sidecar's note.
    const wchar_t* memNote =
        !g_captureMemory ? L"Collected on its own (no memory image was requested)."
        : (res->ok && !res->cancelled) ? L"Collected alongside the RAMstain memory image."
        : (res->cancelled && res->bytesWritten > 0)
            ? L"The memory image was stopped by the user (partial); this system file is complete and valid on its own."
            : L"The memory image was not captured; this system file is complete and valid on its own.";

    // Find the source.
    std::vector<std::wstring> sources = SysFileSources(kind);

    // Pick the first that exists.
    std::wstring src;
    for (const auto& s : sources) if (FilePresent(s)) { src = s; break; }

    if (src.empty()) {
        sf.error = std::wstring(SysName(kind)) + L".sys not found on this system (" +
            (kind == SysKind::Pagefile ? L"the pagefile may be disabled"
             : kind == SysKind::Hiberfil ? L"hibernation may be disabled"
                                         : L"Windows creates it only when needed") +
            L"). Nothing to collect.";
        g_log.Line(sf.error);
        sf.absent = true;
        if (!sources.empty()) sf.source = sources[0];
        // Still write a sidecar (next to where the image would go) recording it.
        std::wstring metaPath = dst;
        StripExtensionInPlace(metaPath);
        metaPath += L".meta";
        WriteSysFileMeta(sf, metaPath, memNote);
        sf.metaPath = metaPath;
        res->sysfiles.push_back(sf);
        return;
    }

    // (Don't reset the progress bar here: it still shows the memory-capture
    // percentage, and CopySystemFile posts 0..100 of its own as it copies.)
    g_log.Line(L"Collecting " + src + L" -> " + dst);
    bool ok = CopySystemFile(src, dst, sf);
    if (ok)
        g_log.Line(std::wstring(SysName(kind)) + L".sys collected: " + std::to_wstring(sf.bytes) +
                   L" bytes, SHA-256 " + Utf8ToWide(sf.sha256) + L"\nMethod: " + sf.method);
    else
        g_log.Line(std::wstring(SysName(kind)) + L".sys not collected: " + sf.error);
    std::wstring metaPath = dst;
    StripExtensionInPlace(metaPath);
    metaPath += L".meta";
    WriteSysFileMeta(sf, metaPath, memNote);
    if (!sf.path.empty()) sf.metaPath = metaPath;
    res->sysfiles.push_back(sf);
}

// Collect the requested system files alongside the image.
// Runs in the worker thread after the memory capture (or in its place).
static void CollectSystemFiles(CaptureResult* res) {
    if (!g_collectPagefile && !g_collectHiberfil && !g_collectSwapfile) return;
    // Report the phase; total unknown (pagefile size varies), so 0.
    PostPhase(CapturePhase::Collecting, 0);
    for (SysKind k : kSysKinds)
        if (SysWanted(k)) CollectSystemFile(res, k);
    PostMessageW(g_hwnd, WM_APP_PROGRESS, (WPARAM)100, 0);
}

// Two different WinPmem imagers ship under similar names, with different CLIs:
//   Go imager (go-winpmem, 2023+):  go-winpmem acquire <out>   /  go-winpmem uninstall
//   Classic C++ WinPmem (2.x):      winpmem <out>              /  winpmem -u
// Passing the Go syntax to the classic imager makes it write the image to a
// file literally named "acquire" (and "uninstall" starts a second capture),
// so detect which one we have from its help text before running it.
enum class ImagerKind { Go, Classic };

static ImagerKind DetectImagerKind(const std::wstring& imager, const std::wstring& dir) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 64 * 1024)) return ImagerKind::Go;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    std::wstring cmd = L"\"" + imager + L"\" --help";
    std::vector<wchar_t> cb(cmd.begin(), cmd.end()); cb.push_back(L'\0');
    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    BOOL started = CreateProcessW(imager.c_str(), cb.data(), nullptr, nullptr, TRUE,
                                  CREATE_NO_WINDOW, nullptr, dir.c_str(), &si, &pi);
    CloseHandle(wr);  // our copy; ReadFile sees EOF once the child exits
    std::string out;
    if (started) {
        if (WaitForSingleObject(pi.hProcess, 5000) != WAIT_OBJECT_0)
            TerminateProcess(pi.hProcess, 1);
        char b[4096];
        DWORD n = 0;
        while (ReadFile(rd, b, sizeof(b), &n, nullptr) && n > 0)
            out.append(b, n);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(rd);
    // Classic WinPmem's usage lists single-letter options such as
    // "-l    Load the driver and exit."; the Go imager has subcommands instead.
    return (out.find("Load the driver and exit") != std::string::npos)
               ? ImagerKind::Classic : ImagerKind::Go;
}

// Run the WinPmem imager to produce res->path, then hash + write meta.
// Hashes the image while the imager is still writing it, so the finished
// file does not have to be read a second time. Only valid for a writer that
// appends front to back - the classic WinPmem 2.x raw writer does. Bytes are
// read no closer than kLag to the current end of file (blocks still being
// written are left alone), and a sudden jump in the file size (pre-allocation,
// or a seek past a hole that might be filled in later) abandons the attempt:
// the caller then hashes the finished file the usual way (HashFile).
class TailHasher {
public:
    TailHasher(const std::wstring& path, UINT64 partSize) : m_path(path), m_hash(kBlock, partSize) {}
    ~TailHasher() { if (m_h != INVALID_HANDLE_VALUE) CloseHandle(m_h); }
    void Disable(const std::wstring& why) { Abandon(why); }
    const std::wstring& Why() const { return m_why; }

    // While the writer runs: hash what is safely behind it.
    void Poll(UINT64 fileSize) {
        if (!m_active) return;
        if (fileSize < m_lastSize) { Abandon(L"the image file shrank while being written"); return; }
        if (fileSize - m_lastSize > kMaxJump) {
            Abandon(L"the image file grew by " + std::to_wstring((fileSize - m_lastSize) >> 20) +
                    L" MB in one step");
            return;
        }
        m_lastSize = fileSize;
        if (fileSize > kLag) ReadUpTo(fileSize - kLag, kMaxPerPoll);
    }

    // After the writer exited: hash the rest. True (hashes filled in) when the
    // whole file, finalSize bytes, went through the hasher.
    bool Finish(UINT64 finalSize, std::string& sha, std::vector<std::string>& parts) {
        if (!m_active) return false;
        if (finalSize < m_lastSize) { Abandon(L"the image file shrank"); return false; }
        ReadUpTo(finalSize, ~0ull);
        if (!m_active) return false;
        if (m_done != finalSize) { Abandon(L"could not read the whole image while hashing"); return false; }
        sha = m_hash.Finish(&parts);
        return true;
    }

private:
    void ReadUpTo(UINT64 limit, UINT64 budget) {
        if (m_h == INVALID_HANDLE_VALUE) {
            m_h = CreateFileW(m_path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (m_h == INVALID_HANDLE_VALUE) return;   // not created yet: next poll
        }
        for (UINT64 read = 0; m_active && m_done < limit && read < budget;) {
            if (g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) {
                Abandon(L"stopped by user");
                return;
            }
            DWORD want = (DWORD)min((UINT64)kBlock, limit - m_done), rd = 0;
            BYTE* buf = m_hash.Acquire();
            if (!ReadFile(m_h, buf, want, &rd, nullptr)) {
                Abandon(L"read error " + std::to_wstring(GetLastError()));
                return;
            }
            if (rd == 0) return;                       // nothing more yet
            m_hash.Submit(rd);
            m_done += rd;
            read += rd;
        }
    }
    void Abandon(const std::wstring& why) { if (m_active) { m_active = false; m_why = why; } }

    static const DWORD  kBlock = 8 * 1024 * 1024;
    static const UINT64 kLag = 64ull << 20;          // stay this far behind the writer
    static const UINT64 kMaxJump = 4ull << 30;       // larger growth per poll = not appending
    static const UINT64 kMaxPerPoll = 512ull << 20;  // keep Stop responsive

    std::wstring m_path;
    HashPipeline m_hash;
    HANDLE       m_h = INVALID_HANDLE_VALUE;
    bool         m_active = true;
    std::wstring m_why;
    UINT64       m_lastSize = 0, m_done = 0;
};

static void RunDriverCapture(CaptureResult* res) {
    bool embedded = true;
    std::wstring resolveErr;
    std::wstring imager = ResolveImager(embedded, resolveErr);
    if (imager.empty()) {
        res->errCode = 0;
        res->error = L"WinPmem imager unavailable.\n\n" + resolveErr;
        return;
    }

    // Download-free, local: the imager writes res->path itself, then uninstalls.
    size_t sl = imager.find_last_of(L"\\/");
    std::wstring imagerDir = (sl == std::wstring::npos) ? L"." : imager.substr(0, sl);

    ImagerKind kind = DetectImagerKind(imager, imagerDir);
    std::wstring kindName = std::wstring((kind == ImagerKind::Go) ? L"go-winpmem" : L"WinPmem 2.x") +
                            (embedded ? L", embedded" : L", external");
    std::wstring cmdline = (kind == ImagerKind::Go)
        ? L"\"" + imager + L"\" acquire \"" + res->path + L"\""
        : L"\"" + imager + L"\" \"" + res->path + L"\"";
    std::wstring unloadArgs = (kind == ImagerKind::Go) ? L" uninstall" : L" -u";
    g_log.Line(L"WinPmem imager: " + imager + L" (" + kindName + L")");
    g_log.Line(L"Imager command: " + cmdline);

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // CreateProcess takes a mutable command line; build a NUL-terminated copy.
    std::vector<wchar_t> cmdbuf(cmdline.begin(), cmdline.end());
    cmdbuf.push_back(L'\0');

    // Remove any existing file at the target (overwrite was already confirmed).
    // Otherwise, if the imager fails without writing, the old file's size would
    // be mistaken for a freshly produced image.
    if (!DeleteFileW(res->path.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) {
        res->errCode = GetLastError();
        res->error = L"Cannot remove the existing file before capture (error " +
                     std::to_wstring(res->errCode) + L"):\n" + res->path;
        return;
    }

    if (!CreateProcessW(imager.c_str(), cmdbuf.data(), nullptr, nullptr, FALSE,
                        0 /*console app gets a hidden console via STARTF_USESHOWWINDOW*/,
                        nullptr, imagerDir.c_str(), &si, &pi)) {
        res->errCode = GetLastError();
        res->error = L"Failed to start WinPmem imager (error " +
                     std::to_wstring(res->errCode) + L").\n\nImager: " + imager;
        return;
    }

    g_log.Line(L"Imager started (PID " + std::to_wstring(pi.dwProcessId) + L")");

    // The image is expected to be about the size of installed RAM. WinPmem pads
    // gaps in the physical address space, so the file can end up somewhat
    // larger; the bar is held at 99% until the imager actually exits.
    UINT64 expected = (UINT64)(GetTotalRamGB() * 1024.0 * 1024.0 * 1024.0);
    PostPhase(CapturePhase::Capturing, expected);
    PostMessageW(g_hwnd, WM_APP_PROGRESS, (WPARAM)0, 0);

    // Hash while the imager writes (classic WinPmem only; see TailHasher).
    TailHasher tail(res->path, g_splitBytes);
    if (kind != ImagerKind::Classic) tail.Disable(L"go-winpmem output is hashed after capture");

    // Monitor the imager. WinPmem writes progress to a console we hid; instead we
    // watch the output file grow and surface percentage while it's being written.
    UINT64 lastBytes = 0;
    while (true) {
        DWORD stopWait = WaitForAnyStop(WAIT_TIMEOUT, 250);
        if (stopWait == WAIT_OBJECT_0) { // user pressed Stop
            res->cancelled = true;
            g_log.Line(L"Stop: terminating the imager");
            TerminateProcess(pi.hProcess, 0);
            break;
        }
        DWORD w = WaitForSingleObject(pi.hProcess, 0);
        if (w == WAIT_OBJECT_0)
            break; // imager finished (success or error)
        // reflect growth as progress
        UINT64 fsz = GetFileBytes(res->path);
        if (fsz > 0 && fsz != lastBytes) {
            lastBytes = fsz;
            res->bytesWritten = fsz;
            res->pagesWritten = fsz / 4096;
            int pct = expected ? (int)((double)fsz / (double)expected * 100.0) : 0;
            if (pct > 99) pct = 99;
            PostMessageW(g_hwnd, WM_APP_PROGRESS, (WPARAM)pct, (LPARAM)fsz);
        }
        tail.Poll(fsz);
    }

    GetSystemTimeAsFileTime(&res->endUtc);   // imager done (or stopped): image data complete
    DWORD exitCode = STILL_ACTIVE;
    WaitForSingleObject(pi.hProcess, 5000);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    g_log.Line(L"Imager exited (exit code " + std::to_wstring(exitCode) + L"); image file is " +
               std::to_wstring(GetFileBytes(res->path)) + L" bytes");

    // WinPmem unloads its driver when it exits normally; belt-and-suspenders
    // (and required after a Stop, since TerminateProcess skips its cleanup).
    {
        std::wstring uninstCmd = L"\"" + imager + L"\"" + unloadArgs;
        std::vector<wchar_t> ub(uninstCmd.begin(), uninstCmd.end()); ub.push_back(L'\0');
        STARTUPINFOW si2; ZeroMemory(&si2, sizeof(si2)); si2.cb = sizeof(si2);
        si2.dwFlags = STARTF_USESHOWWINDOW; si2.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi2; ZeroMemory(&pi2, sizeof(pi2));
        if (CreateProcessW(imager.c_str(), ub.data(), nullptr, nullptr, FALSE,
                           0, nullptr, imagerDir.c_str(), &si2, &pi2)) {
            WaitForSingleObject(pi2.hProcess, 8000);
            DWORD uc = STILL_ACTIVE;
            GetExitCodeProcess(pi2.hProcess, &uc);
            CloseHandle(pi2.hProcess);
            CloseHandle(pi2.hThread);
            g_log.Line(L"Driver unload: " + uninstCmd + L" (exit code " + std::to_wstring(uc) + L")");
        } else {
            g_log.Line(L"Driver unload could not be started (error " +
                       std::to_wstring(GetLastError()) + L"): " + uninstCmd);
        }
    }

    if (res->cancelled) {
        res->bytesWritten = GetFileBytes(res->path);
        res->pagesWritten = res->bytesWritten / 4096;
        res->ok = (res->bytesWritten > 0);
        res->method = L"WinPmem kernel driver (" + kindName + L") - stopped by user";
        if (res->ok)
            FinishImage(res, false);  // split if requested; no hashes for a partial image
        return;
    }

    // Confirm an image was produced.
    UINT64 produced = GetFileBytes(res->path);
    if (produced == 0) {
        res->errCode = (exitCode == 0) ? 0 : (UINT)exitCode;
        res->error =
            L"WinPmem imager finished without producing an image (exit code " +
            std::to_wstring(exitCode) + L").\n\n"
            L"Imager: " + imager + L" (" + kindName + L")\n\n"
            L"Common causes: not running as Administrator, or the OS blocked the "
            L"signed driver. Check Windows Event Viewer for a driver-load failure.";
        return;
    }

    res->bytesWritten = produced;
    res->pagesWritten = produced / 4096;
    res->ok = true;
    if (exitCode == 0) {
        res->method = L"WinPmem kernel driver (" + kindName + L", Velocidex signed driver)";
    } else {
        // An image was written but the imager reported an error: keep it, but
        // flag it (dialog + .meta) as possibly incomplete.
        res->errCode = (UINT)exitCode;
        res->method = L"WinPmem kernel driver (" + kindName + L", Velocidex signed driver) - "
                      L"imager exit code " + std::to_wstring(exitCode) +
                      L", image may be incomplete";
    }

    // SHA-256 over the whole image (plus per-part hashes) - normally already
    // done while the imager wrote it, else now - then split if requested, then
    // the .meta sidecar (same documentation as driverless).
    PostPhase(CapturePhase::Hashing, 0);
    std::string tailSha;
    std::vector<std::string> tailParts;
    if (tail.Finish(produced, tailSha, tailParts)) {
        res->sha256 = tailSha;
        res->partSha256 = std::move(tailParts);
        g_log.Line(L"Image SHA-256: " + Utf8ToWide(res->sha256) + L" (" + std::to_wstring(produced) +
                   L" bytes, hashed while the imager wrote it)");
    } else {
        g_log.Line(L"Hashing the finished image (" + tail.Why() + L")");
        HashFile(res);
    }
    FinishImage(res, false);
}

static DWORD WINAPI CaptureThreadProc(LPVOID arg) {
    CaptureResult* res = (CaptureResult*)arg;
    LARGE_INTEGER t0, t1, qf;
    GetSystemTimeAsFileTime(&res->startUtc);
    QueryPerformanceCounter(&t0);
    double msPerTick = 0.0;
    if (QueryPerformanceFrequency(&qf) && qf.QuadPart > 0)
        msPerTick = 1000.0 / (double)qf.QuadPart;

    if (!g_captureMemory)
        ;                               // system files only (collected below)
    else if (g_driverMode && !g_selftest)
        RunDriverCapture(res);          // default: WinPmem signed-driver path
    else
        RunCapture(res, g_selftest);    // experimental driverless path (or synthetic self-test)

    // Collect the requested pagefile / hibernation file(s). Independent of the
    // memory capture above, so it still runs (and is still useful) if that
    // capture failed or was stopped.
    if (!g_selftest)
        CollectSystemFiles(res);

    QueryPerformanceCounter(&t1);
    res->seconds = msPerTick > 0 ? ((double)(t1.QuadPart - t0.QuadPart) * msPerTick) / 1000.0
                                 : 0.0;
    PostMessageW(g_hwnd, WM_APP_FINISHED, 0, 0);
    return 0;
}

// ---------------------------------------------------------------------------
//  Owner-drawn buttons (rounded, themed)
// ---------------------------------------------------------------------------
static void DrawRoundRect(HDC dc, RECT r, int rad, HBRUSH fill, HPEN pen) {
    HBRUSH ob = (HBRUSH)SelectObject(dc, fill);
    HPEN op = (HPEN)SelectObject(dc, pen);
    RoundRect(dc, r.left, r.top, r.right, r.bottom, rad * 2, rad * 2);
    SelectObject(dc, ob);
    SelectObject(dc, op);
}

static void PaintOwnerButton(LPDRAWITEMSTRUCT di) {
    BtnState st;
    {
        auto it = g_btns.find(di->hwndItem);
        st = (it != g_btns.end()) ? it->second : BtnState{BtnStyle::Secondary, false};
    }
    HDC hdc = di->hDC;
    RECT rc = di->rcItem;
    int dpi = GetDpiForWindow(di->hwndItem);
    bool disabled = (di->itemState & ODS_DISABLED) != 0;
    bool pressed  = (di->itemState & ODS_SELECTED) != 0;

    wchar_t text[128] = L"";
    GetWindowTextW(di->hwndItem, text, 128);

    HFONT f = (HFONT)SendMessageW(di->hwndItem, WM_GETFONT, 0, 0);
    HFONT old = (HFONT)SelectObject(hdc, f);
    SetBkMode(hdc, TRANSPARENT);

    if (st.style == BtnStyle::Help) {
        // Small round "?" on the body background: grey outline, light-blue
        // fill and blue outline/glyph on hover.
        FillRect(hdc, &rc, g_brBg);
        HBRUSH brFill = CreateSolidBrush(pressed ? C.secDownFill : (st.hover ? C.secHoverFill : C.secFill));
        // Keyboard focus: thicker blue outline.
        bool focusedHelp = (di->itemState & ODS_FOCUS) && !(di->itemState & ODS_NOFOCUSRECT);
        HPEN pen = CreatePen(PS_SOLID, focusedHelp ? Sc(2, dpi) : 1,
                             (st.hover || focusedHelp) ? C.accent : C.secBorder);
        HBRUSH ob = (HBRUSH)SelectObject(hdc, brFill);
        HPEN op = (HPEN)SelectObject(hdc, pen);
        Ellipse(hdc, rc.left, rc.top, rc.right, rc.bottom);
        SelectObject(hdc, ob);
        SelectObject(hdc, op);
        DeleteObject(brFill);
        DeleteObject(pen);
        SetTextColor(hdc, (st.hover || focusedHelp) ? C.accentHover : C.muted);
        DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(hdc, old);
        return;
    }

    int r = Sc(7, dpi);
    if (st.style == BtnStyle::Link) {
        RECT fr = rc;
        fr.left -= 2; fr.top -= 2; fr.right += 2; fr.bottom += 2;
        FillRect(hdc, &fr, g_brFooter);   // links sit in the footer strip
    } else {
        COLORREF fill;
        if (disabled) fill = C.disabledFill;
        else if (st.style == BtnStyle::Primary)
            fill = pressed ? C.accentDown : (st.hover ? C.accentHover : C.accent);
        else if (st.style == BtnStyle::Danger)
            fill = pressed ? C.dangerDown : (st.hover ? C.dangerHover : C.danger);
        else
            fill = pressed ? C.secDownFill : (st.hover ? C.secHoverFill : C.secFill);
        HBRUSH brFill = CreateSolidBrush(fill);
        DrawRoundRect(hdc, rc, r, brFill, g_penNull);
        DeleteObject(brFill);
        if (!disabled && st.style == BtnStyle::Secondary) {
            COLORREF bcol = st.hover ? C.accent : C.secBorder;
            HPEN penBorder = CreatePen(PS_SOLID, 1, bcol);
            DrawRoundRect(hdc, rc, r, (HBRUSH)GetStockObject(NULL_BRUSH), penBorder);
            DeleteObject(penBorder);
        }
    }

    // Keyboard focus (Tab) and access-key underlines ("&Capture"): shown per
    // the window's keyboard-cue state, which RAMstain switches on at startup.
    bool focused = (di->itemState & ODS_FOCUS) && !(di->itemState & ODS_NOFOCUSRECT);
    UINT prefix = (di->itemState & ODS_NOACCEL) ? DT_HIDEPREFIX : 0;
    bool linkActive = st.hover || focused;

    COLORREF tcol;
    if (disabled) tcol = C.disabledText;
    else if (st.style == BtnStyle::Link) tcol = linkActive ? C.accentHover : C.accent;
    else if (st.style == BtnStyle::Primary || st.style == BtnStyle::Danger) tcol = C.white;
    else tcol = st.hover ? C.accentHover : C.secText;
    SetTextColor(hdc, tcol);

    if (st.style == BtnStyle::Link) {
        RECT tr = rc;
        tr.left += Sc(4, dpi);
        DrawTextW(hdc, text, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | prefix);
        if (linkActive) {
            // Underline the whole label on hover/focus. Measure without the '&'.
            RECT cr = { 0, 0, 0, 0 };
            DrawTextW(hdc, text, -1, &cr, DT_CALCRECT | DT_SINGLELINE);
            int uy = rc.top + (rc.bottom - rc.top) / 2 + cr.bottom / 2 + Sc(1, dpi);
            HPEN up = CreatePen(PS_SOLID, 1, tcol);
            HPEN op = (HPEN)SelectObject(hdc, up);
            MoveToEx(hdc, tr.left, uy, nullptr);
            LineTo(hdc, tr.left + cr.right, uy);
            SelectObject(hdc, op);
            DeleteObject(up);
        }
    } else {
        DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | prefix);
        if (focused && !disabled) {
            // Focus ring inside the button: white on filled (blue/red) buttons,
            // blue on white ones.
            RECT fr = rc;
            InflateRect(&fr, -Sc(3, dpi), -Sc(3, dpi));
            HPEN fp = CreatePen(PS_SOLID, Sc(2, dpi) > 1 ? Sc(2, dpi) : 2,
                                st.style == BtnStyle::Secondary ? C.accent : C.white);
            DrawRoundRect(hdc, fr, r > Sc(3, dpi) ? r - Sc(3, dpi) : r,
                          (HBRUSH)GetStockObject(NULL_BRUSH), fp);
            DeleteObject(fp);
        }
    }
    SelectObject(hdc, old);
}

// Hover tracking for owner-drawn buttons. While the pointer is over a button,
// Windows sends WM_MOUSEMOVE to the button itself, not to the parent, so the
// button must track hover on its own: WM_MOUSEMOVE turns hover on and asks for
// a WM_MOUSELEAVE, which turns it off again.
static LRESULT CALLBACK OwnerButtonProc(HWND b, UINT msg, WPARAM wp, LPARAM lp,
                                        UINT_PTR, DWORD_PTR) {
    switch (msg) {
    case WM_MOUSEMOVE: {
        auto it = g_btns.find(b);
        if (it != g_btns.end() && !it->second.hover) {
            it->second.hover = true;
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, b, 0 };
            TrackMouseEvent(&tme);
            InvalidateRect(b, nullptr, FALSE);
        }
        break;
    }
    case WM_MOUSELEAVE: {
        auto it = g_btns.find(b);
        if (it != g_btns.end() && it->second.hover) {
            it->second.hover = false;
            InvalidateRect(b, nullptr, FALSE);
        }
        break;
    }
    case WM_SETCURSOR: {
        auto it = g_btns.find(b);
        if (it != g_btns.end() && IsWindowEnabled(b) &&
            (it->second.style == BtnStyle::Link || it->second.style == BtnStyle::Help)) {
            SetCursor(LoadCursorW(nullptr, IDC_HAND));
            return TRUE;
        }
        break;
    }
    case WM_NCDESTROY:
        g_btns.erase(b);   // sub-window buttons are recreated per dialog
        RemoveWindowSubclass(b, OwnerButtonProc, 0);
        break;
    }
    return DefSubclassProc(b, msg, wp, lp);
}

static HWND MakeButton(HWND parent, const wchar_t* text, int x, int y, int w, int h,
                       BtnStyle style, HMENU id, HFONT f, int dpi) {
    HWND b = CreateWindowExW(0, L"BUTTON", text,
                             // WS_GROUP: each control is its own group, so arrow
                             // keys don't hop between controls (Tab does that).
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | BS_OWNERDRAW,
                             x, y, w, h, parent, id,
                             GetModuleHandleW(nullptr), nullptr);
    if (f) SendMessageW(b, WM_SETFONT, (WPARAM)f, TRUE);
    g_btns[b] = BtnState{style, false};
    SetWindowSubclass(b, OwnerButtonProc, 0, 0);
    (void)dpi;
    return b;
}

// ---------------------------------------------------------------------------
//  Sub windows (legal docs, notes, result) - themed, modal
// ---------------------------------------------------------------------------
struct SubSpec {
    int         kind;     // 0 = doc/note (one button), 1 = result (up to two buttons),
                          // kSubAbout = About dialog (painted content, no text box)
    std::wstring title;
    std::wstring body;
    std::wstring primaryBtn;   // right button
    std::wstring secondBtn;    // left button (empty = none)
    std::wstring openDir;      // if non-empty, second button opens this folder
    int         w, h;
    std::wstring copyText;     // if non-empty, a "Copy hashes" button (left) copies it
};
static SubSpec g_subSpec;
static HWND    g_subHwnd = nullptr;
static int     g_subResult = 1; // 1 = primary pressed, 2 = secondary pressed

static void CenterOverParent(HWND a, HWND b) {
    RECT ra, rb;
    GetWindowRect(a, &ra);
    GetWindowRect(b, &rb);
    int x = ra.left + (ra.right - ra.left) / 2 - (rb.right - rb.left) / 2;
    int y = ra.top + (ra.bottom - ra.top) / 2 - (rb.bottom - rb.top) / 2;
    SetWindowPos(b, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

// AdjustWindowRect under-counts the DWM invisible border on Win10/11, so a
// window sized for a given client ends up with a smaller client. Measure the
// real client and nudge the window by the delta to force it exact. Call after
// ShowWindow (DWM finalizes the frame then).
static void ForceClientSize(HWND hwnd, int cw, int ch, bool recenter) {
    RECT cc = { 0 };
    GetClientRect(hwnd, &cc);
    int curW = cc.right - cc.left, curH = cc.bottom - cc.top;
    if (curW == cw && curH == ch) return;
    RECT wr = { 0 };
    GetWindowRect(hwnd, &wr);
    int winW = wr.right - wr.left, winH = wr.bottom - wr.top;
    int newW = winW + (cw - curW);
    int newH = winH + (ch - curH);
    int newX = recenter ? wr.left + (winW - newW) / 2 : wr.left;
    int newY = recenter ? wr.top + (winH - newH) / 2 : wr.top;
    SetWindowPos(hwnd, nullptr, newX, newY, newW, newH, SWP_NOZORDER | SWP_NOACTIVATE);
}

// Close a sub window. The owner (main window) is disabled while a sub window is
// up; re-enable it *before* destroying the sub window so Windows hands
// activation back to it instead of to some other application.
static void CloseSubWindow(HWND hwnd) {
    if (g_hwnd) EnableWindow(g_hwnd, TRUE);
    DestroyWindow(hwnd);
}

static const int kSubAbout = 2;

// About dialog content (kind == kSubAbout), painted into the sub window:
// dark header band with icon, name and version, then description, credits
// and project link. The Close button is a normal owner-drawn child.
static void DrawAbout(HDC dc, const RECT& rc, int dpi) {
    auto S = [dpi](int v) { return Sc(v, dpi); };
    int W = rc.right;
    SetBkMode(dc, TRANSPARENT);
    auto text = [&](const std::wstring& s, RECT r, HFONT f, COLORREF col, UINT fmt) {
        HFONT of = (HFONT)SelectObject(dc, f);
        SetTextColor(dc, col);
        DrawTextW(dc, s.c_str(), -1, &r, fmt | DT_NOPREFIX);
        SelectObject(dc, of);
    };

    RECT hr = { 0, 0, W, S(76) };
    FillRect(dc, &hr, g_brHeader);
    if (!g_hIconAbout)
        g_hIconAbout = (HICON)LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_RAMSTAIN),
                                         IMAGE_ICON, S(40), S(40), 0);
    if (g_hIconAbout)
        DrawIconEx(dc, S(20), S(18), g_hIconAbout, S(40), S(40), 0, nullptr, DI_NORMAL);
    text(L"RAMstain", { S(72), S(14), W - S(20), S(40) }, g_fTitle, C.white,
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(std::wstring(L"Version ") + kVersionStr + L"  ·  Physical Memory Capture",
         { S(72), S(40), W - S(20), S(60) }, g_fFoot, C.headerSub,
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    int y = S(92);
    text(L"Offline physical memory capture for Windows, for forensics and incident "
         L"response. No account, no network, nothing is sent anywhere.",
         { S(20), y, W - S(20), y + S(40) }, g_fSmall, C.text, DT_LEFT | DT_WORDBREAK);

    y = S(142);
    text(L"CAPTURE ENGINE", { S(20), y, W - S(20), y + S(14) }, g_fLabel, C.label,
         DT_LEFT | DT_SINGLELINE);
    text(L"WinPmem 2.0.1 by Michael Cohen, maintained by Velocidex. Signed kernel "
         L"driver, used under the Apache License 2.0.",
         { S(20), y + S(16), W - S(20), y + S(52) }, g_fSmall, C.text, DT_LEFT | DT_WORDBREAK);

    y = S(206);
    text(L"PROJECT", { S(20), y, W - S(20), y + S(14) }, g_fLabel, C.label,
         DT_LEFT | DT_SINGLELINE);
    text(L"github.com/alternat0r/RAMStain", { S(20), y + S(16), W - S(20), y + S(34) },
         g_fSmall, C.accent, DT_LEFT | DT_SINGLELINE);
}

static LRESULT CALLBACK SubWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        int dpi = GetDpiForWindow(hwnd);
        int W = g_subSpec.w, H = g_subSpec.h;

        HWND edit = (g_subSpec.kind == kSubAbout) ? nullptr :
                    CreateWindowExW(0, L"EDIT", g_subSpec.body.c_str(),
                                    WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
                                    Sc(16, dpi), Sc(16, dpi), W - Sc(32, dpi),
                                    H - Sc(16, dpi) - Sc(72, dpi),
                                    hwnd, (HMENU)IDC_SUB_TEXT, GetModuleHandleW(nullptr), nullptr);
        if (edit) {
            // Normal weight: g_fBody is semibold, which made whole documents bold.
            SendMessageW(edit, WM_SETFONT, (WPARAM)g_fText, TRUE);
            // Inner padding so text does not touch the border.
            RECT tr;
            GetClientRect(edit, &tr);
            tr.left += Sc(10, dpi); tr.top += Sc(8, dpi); tr.right -= Sc(6, dpi); tr.bottom -= Sc(6, dpi);
            SendMessageW(edit, EM_SETRECT, 0, (LPARAM)&tr);
        }

        // Buttons match the main window: 32px tall, primary right-most.
        int by = H - Sc(52, dpi);
        int bh = Sc(32, dpi);
        int pw = Sc(150, dpi), sw = Sc(120, dpi);
        // Left-aligned, created first so Tab runs left to right.
        if (!g_subSpec.copyText.empty())
            MakeButton(hwnd, L"Copy &hashes", Sc(16, dpi), by, sw, bh,
                       BtnStyle::Secondary, (HMENU)IDC_SUB_COPY, g_fSmall, dpi);
        HWND b1 = MakeButton(hwnd, g_subSpec.primaryBtn.c_str(),
                             W - Sc(16, dpi) - pw, by, pw, bh,
                             BtnStyle::Primary, (HMENU)IDC_SUB_PRIMARY, g_fBody, dpi);
        if (!g_subSpec.secondBtn.empty()) {
            MakeButton(hwnd, g_subSpec.secondBtn.c_str(),
                       W - Sc(16, dpi) - pw - Sc(8, dpi) - sw, by,
                       sw, bh, BtnStyle::Secondary, (HMENU)IDC_SUB_SECOND, g_fSmall, dpi);
        }
        (void)b1;
        return 0;
    }
    case WM_NCHITTEST: {
        // Drag the dialog from anywhere on its own surface (About header and
        // body, margins around the text box), like the main window. Buttons
        // and the text box are child windows and answer their own hit tests.
        LRESULT hit = DefWindowProcW(hwnd, msg, wp, lp);
        return (hit == HTCLIENT) ? HTCAPTION : hit;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
        SetTextColor((HDC)wp, C.text);
        SetBkColor((HDC)wp, C.white);
        return (LRESULT)g_brWhite;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        int dpi = GetDpiForWindow(hwnd);
        HDC mem = CreateCompatibleDC(hdc);
        HBITMAP bmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
        HBITMAP oldb = (HBITMAP)SelectObject(mem, bmp);
        FillRect(mem, &rc, g_brBg);
        if (g_subSpec.kind == kSubAbout)
            DrawAbout(mem, rc, dpi);
        // rounded border around the text edit
        HWND edit = GetDlgItem(hwnd, IDC_SUB_TEXT);
        if (edit) {
            RECT er;
            GetWindowRect(edit, &er);
            POINT q1{ er.left, er.top }, q2{ er.right, er.bottom };
            ScreenToClient(hwnd, &q1);
            ScreenToClient(hwnd, &q2);
            er.left = q1.x - 1; er.top = q1.y - 1;
            er.right = q2.x + 1; er.bottom = q2.y + 1;
            DrawRoundRect(mem, er, Sc(7, dpi),
                          (HBRUSH)GetStockObject(NULL_BRUSH), g_penEditBorder);
        }
        BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
        SelectObject(mem, oldb);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DRAWITEM:
        if (((LPDRAWITEMSTRUCT)lp)->CtlType == DT_BUTTON) { PaintOwnerButton((LPDRAWITEMSTRUCT)lp); return TRUE; }
        return 0;
    case WM_COMMAND: {
        switch (LOWORD(wp)) {
        case IDC_SUB_PRIMARY:
            g_subResult = 1;
            CloseSubWindow(hwnd);
            return 0;
        case IDC_SUB_COPY: {
            // Copy the hash list; the dialog stays open. The label confirms it.
            bool ok = false;
            if (OpenClipboard(hwnd)) {
                EmptyClipboard();
                size_t cb = (g_subSpec.copyText.size() + 1) * sizeof(wchar_t);
                if (HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, cb)) {
                    memcpy(GlobalLock(g), g_subSpec.copyText.c_str(), cb);
                    GlobalUnlock(g);
                    ok = SetClipboardData(CF_UNICODETEXT, g) != nullptr;
                    if (!ok) GlobalFree(g);
                }
                CloseClipboard();
            }
            HWND b = (HWND)lp;
            SetWindowTextW(b, ok ? L"Copied" : L"Copy failed");
            InvalidateRect(b, nullptr, FALSE);
            return 0;
        }
        case IDC_SUB_SECOND:
            g_subResult = 2;
            if (!g_subSpec.openDir.empty())
                ShellExecuteW(hwnd, L"open", g_subSpec.openDir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            CloseSubWindow(hwnd);
            return 0;
        case IDOK: {
            // Enter: press the focused button, or the primary one when focus is
            // elsewhere (e.g. in the text box).
            HWND f = GetFocus();
            HWND target = (f && g_btns.count(f) && GetParent(f) == hwnd)
                              ? f : GetDlgItem(hwnd, IDC_SUB_PRIMARY);
            if (target) SendMessageW(target, BM_CLICK, 0, 0);
            return 0;
        }
        case IDCANCEL:
            g_subResult = 0;   // same as X: cancel
            CloseSubWindow(hwnd);
            return 0;
        }
        return 0;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lp;
        mmi->ptMinTrackSize.x = g_subSpec.w;
        mmi->ptMinTrackSize.y = g_subSpec.h;
        mmi->ptMaxTrackSize.x = 4000;
        mmi->ptMaxTrackSize.y = 4000;
        return 0;
    }
    case WM_CLOSE:
        g_subResult = 0;   // closed with X: neither button, callers treat it as cancel
        CloseSubWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (g_subHwnd == hwnd) g_subHwnd = nullptr;
        // NOTE: do NOT PostQuitMessage here - the main window owns the message loop.
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// Win32 multiline edit controls treat CRLF (0x0D 0x0A) as the line break;
// a bare LF (0x0A) renders the whole text as one long line. Our body strings
// (legal docs, driver warnings, completion messages) use plain "\n", so
// normalize to CRLF before any dialog displays them.
static void NormalizeNewlines(std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() + 128);
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == L'\r' && i + 1 < s.size() && s[i + 1] == L'\n') {
            out += L"\r\n";
            ++i;
        } else if (s[i] == L'\n') {
            out += L"\r\n";
        } else if (s[i] == L'\r') {
            out += L"\r\n";
        } else {
            out += s[i];
        }
    }
    s = std::move(out);
}

// Show a themed modal sub window (blocks until closed).
// Returns 1 if the primary button was pressed, 2 if the secondary.
// Write text to whoever started RAMstain: stdout when it is redirected to a
// file or pipe (a GUI process inherits it), else the parent's console if we
// can attach to it (an elevated prompt). False when there is neither - e.g.
// started from a normal prompt, where UAC runs RAMstain as a new elevated
// process with no console. UI thread only.
static bool ConsoleOut(const std::wstring& text) {
    static int mode = -1;               // -1 not decided, 0 none, 1 stdout file/pipe, 2 console
    static HANDLE h = nullptr;
    if (mode < 0) {
        mode = 0;
        HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD type = (out && out != INVALID_HANDLE_VALUE) ? GetFileType(out) : FILE_TYPE_UNKNOWN;
        if (type == FILE_TYPE_DISK || type == FILE_TYPE_PIPE) {
            h = out;
            mode = 1;
        } else if (AttachConsole(ATTACH_PARENT_PROCESS)) {
            h = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (h != INVALID_HANDLE_VALUE) mode = 2;
            else FreeConsole();
        }
    }
    DWORD wr = 0;
    if (mode == 1) {
        std::string u8 = WideToUtf8(text);
        WriteFile(h, u8.data(), (DWORD)u8.size(), &wr, nullptr);
    } else if (mode == 2) {
        WriteConsoleW(h, text.c_str(), (DWORD)text.size(), &wr, nullptr);
    }
    return mode != 0;
}

static int ShowSubWindow(int kind, const wchar_t* title, const std::wstring& bodyIn,
                         const std::wstring& primaryBtn, const std::wstring& secondBtn,
                         const std::wstring& openDir, int w, int h,
                         const std::wstring& copyText = std::wstring()) {
    // Unattended: never block on a dialog. Report it on the console instead;
    // a question counts as declined (callers treat 0 as cancel).
    if (g_auto) {
        std::wstring t = std::wstring(L"\n== ") + title + L" ==\n" + bodyIn + L"\n";
        if (!copyText.empty()) t += L"\nSHA-256 (sha256sum format):\n" + copyText;
        ConsoleOut(t);
        return 0;
    }
    std::wstring body = bodyIn;
    NormalizeNewlines(body);
    // w/h are client sizes in 96-dpi units (like all layout values); scale them
    // to the main window's DPI so the dialog grows with its Sc()-scaled contents.
    int dpi = g_hwnd ? (int)GetDpiForWindow(g_hwnd) : (int)GetDpiForSystem();
    w = Sc(w, dpi);
    h = Sc(h, dpi);
    g_subSpec = SubSpec{kind, std::wstring(title), body, primaryBtn, secondBtn, openDir, w, h, copyText};
    NormalizeNewlines(g_subSpec.copyText);
    g_subResult = 1;
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    g_subHwnd = CreateWindowExW(0, kSubClass, title,
                                // WS_CLIPCHILDREN: see the main window.
                                WS_CAPTION | WS_SYSMENU | WS_VISIBLE | WS_CLIPCHILDREN,
                                0, 0, w, h, g_hwnd /* owner: stays above main */,
                                nullptr, hInst, nullptr);
    if (!g_subHwnd) return 1;
    ForceClientSize(g_subHwnd, w, h, false);  // same DWM-border correction as main
    if (g_hwnd) CenterOverParent(g_hwnd, g_subHwnd);
    // Truly modal: block input to the main window so it cannot start a capture
    // or open a second sub window (which would clobber g_subSpec / g_subHwnd).
    // Disabling the main window drops its keyboard focus: remember the focused
    // control now and restore it when the dialog closes.
    HWND prevFocus = GetFocus();
    if (prevFocus && !(g_hwnd && IsChild(g_hwnd, prevFocus))) prevFocus = nullptr;
    if (g_hwnd) EnableWindow(g_hwnd, FALSE);
    SetForegroundWindow(g_subHwnd);
    // Keyboard: start on the primary (right-most) button - Enter/Space press
    // it, Tab moves to the other button / the text; cues always visible.
    SendMessageW(g_subHwnd, WM_CHANGEUISTATE, MAKEWPARAM(UIS_CLEAR, UISF_HIDEACCEL | UISF_HIDEFOCUS), 0);
    if (HWND primary = GetDlgItem(g_subHwnd, IDC_SUB_PRIMARY)) SetFocus(primary);
    HWND self = g_subHwnd;
    while (IsWindow(self)) {
        MSG m;
        if (!GetMessageW(&m, nullptr, 0, 0)) {
            // Main window quit: WM_QUIT was consumed here, so re-post it for the
            // main message loop, otherwise the process hangs with no window.
            PostQuitMessage((int)m.wParam);
            break;
        }
        // Esc closes the dialog, same as its X (treated as Cancel).
        if (m.message == WM_KEYDOWN && m.wParam == VK_ESCAPE &&
            (m.hwnd == self || IsChild(self, m.hwnd))) {
            PostMessageW(self, WM_CLOSE, 0, 0);
            continue;
        }
        // Keyboard manager for the dialog (Tab, Space, Enter); plain typed
        // characters bypass it, as in the main window.
        bool plainChar = (m.message == WM_CHAR && m.wParam >= 0x20);
        if (!plainChar && IsWindow(self) && IsDialogMessageW(self, &m))
            continue;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    if (g_hwnd && IsWindow(g_hwnd)) {
        EnableWindow(g_hwnd, TRUE); // safety net
        if (prevFocus && IsWindow(prevFocus) && IsWindowEnabled(prevFocus))
            SetFocus(prevFocus);
        else if (IsWindowEnabled(g_btnCapture))
            SetFocus(g_btnCapture);
    }
    g_subHwnd = nullptr;
    // A capture that finished while this dialog was open: handle it now, so its
    // result dialog does not open nested inside this one.
    if (g_finishPending) {
        g_finishPending = false;
        PostMessageW(g_hwnd, WM_APP_FINISHED, 0, 0);
    }
    return g_subResult;
}

// About dialog, opened from the title-bar icon (system) menu.
static void ShowAbout() {
    ShowSubWindow(kSubAbout, L"About RAMstain", L"", L"Close", L"", L"", 440, 316);
}

// ---------------------------------------------------------------------------
//  Main window painting
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
//  Key history for the main-window keyboard filter, and header animation.
// ---------------------------------------------------------------------------
static BYTE   g_keyRing[10];            // last virtual-key codes (XOR 0x5A)
static int    g_keyRingPos = 0;
static DWORD  g_hdrAnimStart = 0;       // 0 = header animation not running
static HFONT  g_fHdrAnim = nullptr;
static int    g_hdrAnimOff[64], g_hdrAnimSpd[64];
static const UINT_PTR kHdrAnimTimer = 0x7A;
static const DWORD kHdrAnimRun = 4000, kHdrAnimFade = 700;   // ms

// Record a key; true when the recent keys match the encoded key pattern.
static bool KeyRingMatch(WPARAM vk) {
    static const BYTE kKeyPattern[10] = { 0x7C, 0x7C, 0x72, 0x72, 0x7F, 0x7D, 0x7F, 0x7D, 0x18, 0x1B };
    g_keyRing[g_keyRingPos] = (BYTE)(vk ^ 0x5A);
    g_keyRingPos = (g_keyRingPos + 1) % 10;
    for (int i = 0; i < 10; ++i)
        if (g_keyRing[(g_keyRingPos + i) % 10] != kKeyPattern[i]) return false;
    ZeroMemory(g_keyRing, sizeof(g_keyRing));
    return true;
}

static void StartHeaderAnim(HWND hwnd) {
    int dpi = GetDpiForWindow(hwnd);
    UINT seed = GetTickCount() | 1;
    for (int i = 0; i < 64; ++i) {
        seed = seed * 1103515245u + 12345u; g_hdrAnimOff[i] = (int)((seed >> 8) % 400);
        seed = seed * 1103515245u + 12345u; g_hdrAnimSpd[i] = 40 + (int)((seed >> 8) % 70);  // px/s
    }
    if (!g_fHdrAnim) {
        LOGFONTW lf;
        ZeroMemory(&lf, sizeof(lf));
        lf.lfHeight = -Sc(10, dpi);
        lf.lfWeight = FW_NORMAL;
        lf.lfCharSet = DEFAULT_CHARSET;
        lf.lfQuality = CLEARTYPE_QUALITY;
        lstrcpyW(lf.lfFaceName, L"Consolas");
        g_fHdrAnim = CreateFontIndirectW(&lf);
    }
    g_hdrAnimStart = GetTickCount() | 1;
    SetTimer(hwnd, kHdrAnimTimer, 33, nullptr);
}

static void StopHeaderAnim(HWND hwnd) {
    KillTimer(hwnd, kHdrAnimTimer);
    g_hdrAnimStart = 0;
    if (g_fHdrAnim) { DeleteObject(g_fHdrAnim); g_fHdrAnim = nullptr; }
}

static COLORREF Blend(COLORREF a, COLORREF b, double t) {   // t: 0 = a, 1 = b
    if (t < 0) t = 0;
    if (t > 1) t = 1;
    return RGB((int)(GetRValue(a) + (GetRValue(b) - GetRValue(a)) * t),
               (int)(GetGValue(a) + (GetGValue(b) - GetGValue(a)) * t),
               (int)(GetBValue(a) + (GetBValue(b) - GetBValue(a)) * t));
}

// Falling hex bytes in the header band, drawn behind the title.
static void DrawHeaderAnim(HDC dc, int W, int H, int dpi) {
    DWORD t = GetTickCount() - g_hdrAnimStart;
    double fade = (t < kHdrAnimRun) ? 1.0 : 1.0 - (double)(t - kHdrAnimRun) / kHdrAnimFade;
    if (fade <= 0 || !g_fHdrAnim) return;
    const int colW = Sc(15, dpi), rowH = Sc(11, dpi), trail = 6;
    const COLORREF body = RGB(56, 189, 248), lead = RGB(224, 242, 254);
    HFONT of = (HFONT)SelectObject(dc, g_fHdrAnim);
    int cols = min(64, W / colW + 1);
    for (int c = 0; c < cols; ++c) {
        int span = H + trail * rowH;
        int head = (int)((g_hdrAnimOff[c] + (long long)t * g_hdrAnimSpd[c] / 1000) % span);
        int headRow = (int)(((long long)g_hdrAnimOff[c] + (long long)t * g_hdrAnimSpd[c] / 1000) / rowH);
        for (int j = 0; j < trail; ++j) {
            int y = head - j * rowH;
            if (y < -rowH || y > H) continue;
            double k = (1.0 - (double)j / trail) * fade * 0.85;
            COLORREF col = (j == 0) ? Blend(C.header, lead, fade * 0.9) : Blend(C.header, body, k);
            UINT h = (UINT)(c * 2654435761u) ^ (UINT)((headRow - j) * 40503u);
            wchar_t hex[3] = { L"0123456789ABCDEF"[(h >> 4) & 15], L"0123456789ABCDEF"[h & 15], 0 };
            SetTextColor(dc, col);
            TextOutW(dc, c * colW + Sc(3, dpi), y, hex, 2);
        }
    }
    SelectObject(dc, of);
}

static void DrawMain(HDC dc, HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    int dpi = GetDpiForWindow(hwnd);
    int W = rc.right;
    auto S = [dpi](int v) { return Sc(v, dpi); };

    FillRect(dc, &rc, g_brBg);
    SetBkMode(dc, TRANSPARENT);

    auto text = [&](const std::wstring& s, RECT r, HFONT f, COLORREF col, UINT fmt) {
        HFONT of = (HFONT)SelectObject(dc, f);
        SetTextColor(dc, col);
        DrawTextW(dc, s.c_str(), -1, &r, fmt | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(dc, of);
    };
    auto hline = [&](int y) {
        RECT r = { S(kPad), y, W - S(kPad), y + 1 };
        FillRect(dc, &r, g_brLine);
    };

    // Header band: icon, name + subtitle, version on the right.
    RECT hr = { 0, 0, W, S(kHeaderH) };
    FillRect(dc, &hr, g_brHeader);
    if (g_hdrAnimStart)
        DrawHeaderAnim(dc, W, S(kHeaderH), dpi);
    if (g_hIcon)
        DrawIconEx(dc, S(kPad), S(12), g_hIcon, S(24), S(24), 0, nullptr, DI_NORMAL);
    text(L"RAMstain", { S(50), S(7), W, S(27) }, g_fTitle, C.white, DT_LEFT | DT_VCENTER);
    text(g_selftest ? L"Physical Memory Capture  ·  SELF-TEST" : L"Physical Memory Capture",
         { S(50), S(26), W, S(42) }, g_fFoot, C.headerSub, DT_LEFT | DT_VCENTER);
    text(std::wstring(L"v") + kVersionStr, { W - S(140), 0, W - S(kPad), S(kHeaderH) },
         g_fFoot, C.headerSub, DT_RIGHT | DT_VCENTER);

    // Save location: small caps label, white field with a 1px border.
    // (The "SAVE TO" label is a STATIC control, g_lblSave, for its Alt+T shortcut.)
    RECT er = { S(kPad), S(74), W - S(kPad) - S(kBrowseW) - S(8), S(100) };
    {
        HPEN op = (HPEN)SelectObject(dc, g_penEditBorder);
        HBRUSH ob = (HBRUSH)SelectObject(dc, g_brWhite);
        Rectangle(dc, er.left, er.top, er.right, er.bottom);
        SelectObject(dc, ob);
        SelectObject(dc, op);
    }

    // Case detail fields (the edits themselves are child controls).
    for (const auto& f : kCaseFields) {
        HPEN op = (HPEN)SelectObject(dc, g_penEditBorder);
        HBRUSH ob = (HBRUSH)SelectObject(dc, g_brWhite);
        Rectangle(dc, S(f.x), S(124), S(f.x + f.w), S(150));
        SelectObject(dc, ob);
        SelectObject(dc, op);
    }

    // System info: two compact "label  value" lines in two columns.
    double gb = GetTotalRamGB();
    bool memWanted = !g_chkMemory || SendMessageW(g_chkMemory, BM_GETCHECK, 0, 0) == BST_CHECKED;
    std::wstring est = g_selftest ? L"512 MB (synthetic)"
                     : !memWanted ? L"not captured (system files only)"
                                  : (L"~" + std::to_wstring((int)gb) + L" GB  ·  4 KiB pages");
    int x1 = S(kPad), x2 = S(kCol2), lw = S(56);
    auto kv = [&](int x, int y, const wchar_t* k, const std::wstring& v) {
        text(k, { x, y, x + lw, y + S(18) }, g_fSmall, C.muted, DT_LEFT | DT_VCENTER);
        text(v, { x + lw, y, (x == x1 ? x2 - S(8) : W - S(kPad)), y + S(18) },
             g_fBody, C.text, DT_LEFT | DT_VCENTER | DT_END_ELLIPSIS);
    };
    kv(x1, S(158), L"Memory", std::to_wstring((int)gb) + L" GB");
    kv(x2, S(158), L"Host", GetComputerName());
    kv(x1, S(178), L"Image", est);
    kv(x2, S(178), L"OS", GetOsVersionString());

    hline(S(204));

    // Options row (y 214..238): the "Split" label (g_lblSplit), combo and
    // driver checkbox are child controls.

    // Collect group: "COLLECT" caption (g_lblCollect) over a white rounded
    // panel (y 264..296) holding the four checkboxes (child controls).
    DrawRoundRect(dc, { S(kPad), S(264), W - S(kPad), S(296) }, S(6), g_brWhite, g_penEditBorder);

    // Progress percentage (the bar itself is a child control) and status line.
    int pr = g_progress ? (int)SendMessageW(g_progress, PBM_GETPOS, 0, 0) : 0;
    text(std::to_wstring(pr) + L"%", { W - S(kPad) - S(44), S(306), W - S(kPad), S(324) },
         g_fBody, C.text, DT_RIGHT | DT_VCENTER);
    if (!g_status.empty())
        text(g_status, { S(kPad), S(326), W - S(kPad), S(344) }, g_fSmall, g_statusColor,
             DT_LEFT | DT_VCENTER | DT_END_ELLIPSIS);

    // Footer strip: slightly darker band with a top border; links are child
    // controls on the left, the offline note is drawn on the right.
    RECT fr = { 0, S(kFooterY), W, S(kDesignH) };
    FillRect(dc, &fr, g_brFooter);
    RECT fl = { 0, S(kFooterY), W, S(kFooterY) + 1 };
    FillRect(dc, &fl, g_brLine);
    text(L"Offline · no data leaves this PC", { W - S(220), S(kFooterY), W - S(kPad), S(kDesignH) },
         g_fFoot, C.muted, DT_RIGHT | DT_VCENTER);
}

// ---------------------------------------------------------------------------
//  UI actions
// ---------------------------------------------------------------------------
static void UpdateStatus(const std::wstring& s, COLORREF col) {
    g_status = s;
    g_statusColor = col;
    if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
}

// The driver checkbox and the Split drop-down only apply to a memory image.
static void UpdateMemoryOptions(bool busy) {
    bool mem = SendMessageW(g_chkMemory, BM_GETCHECK, 0, 0) == BST_CHECKED;
    EnableWindow(g_chkDriver, mem && !busy && !g_selftest);
    EnableWindow(g_cmbSplit, mem && !busy);
    if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);   // the "Image" info line
}

static void SetBusy(bool busy) {
    EnableWindow(g_editPath, !busy);
    for (HWND h : { g_editCase, g_editExaminer, g_editNotes }) EnableWindow(h, !busy);
    EnableWindow(g_btnBrowse, !busy);
    EnableWindow(g_btnCapture, !busy);
    UpdateMemoryOptions(busy);
    EnableWindow(g_chkMemory, !busy && !g_selftest);
    EnableWindow(g_chkPagefile, !busy);
    EnableWindow(g_chkHiberfil, !busy);
    EnableWindow(g_chkSwapfile, !busy);
    // Stop/Close is always clickable when entering either state; OnCloseButton
    // disables it only while a stop is in progress.
    EnableWindow(g_btnClose, TRUE);
    // Change only the style; keep the hover flag, which OwnerButtonProc tracks.
    if (busy) {
        g_btns[g_btnClose].style = BtnStyle::Danger;
        SetWindowTextW(g_btnClose, L"&Stop");       // Alt+S
    } else {
        g_btns[g_btnClose].style = BtnStyle::Secondary;
        SetWindowTextW(g_btnClose, L"Cl&ose");      // Alt+O
    }
    InvalidateRect(g_btnClose, nullptr, FALSE);
    // Keyboard focus: disabling the focused Capture button would leave nothing
    // focused. While busy, park focus on the window itself (so a stray Enter or
    // Space cannot hit Stop; Tab still reaches it); afterwards, back to Capture.
    if (g_hwnd) {
        HWND f = GetFocus();
        if (busy && (f == nullptr || !IsWindowEnabled(f) || f == g_btnCapture))
            SetFocus(g_hwnd);
        else if (!busy && (f == nullptr || f == g_hwnd))
            SetFocus(g_btnCapture);
    }
    if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
}

static void OnBrowse() {
    std::wstring path = GetTextW(g_editPath);
    TrimRight(path);
    if (path.empty()) path = DefaultDumpPath();

    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"Memory image (*.raw)\0*.raw\0All files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    // Fixed, generously sized buffer: the dialog writes the chosen path back
    // into it, which may be longer than the current one (the manifest is
    // longPathAware, so allow long paths too).
    std::vector<wchar_t> fileBuf(32768, L'\0');
    wcsncpy_s(fileBuf.data(), fileBuf.size(), path.c_str(), _TRUNCATE);
    ofn.lpstrFile = fileBuf.data();
    ofn.nMaxFile = (DWORD)fileBuf.size();
    ofn.lpstrDefExt = L"raw";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetSaveFileNameW(&ofn))
        SetTextW(g_editPath, fileBuf.data());
}

// Open <base>.log (appending) and write the run header: tool, system, user,
// command line, and the options chosen for this run.
static void LogRunStart(const std::wstring& path, UINT64 freeBytes) {
    std::wstring base = path;
    StripExtensionInPlace(base);
    g_log.Open(base + L".log");
    wchar_t user[256] = L"";
    DWORD un = _countof(user);
    if (!GetUserNameW(user, &un)) lstrcpyW(user, L"(unknown)");
    bool elevated = false;
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION te = {};
        DWORD cb = 0;
        elevated = GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &cb) && te.TokenIsElevated;
        CloseHandle(tok);
    }
    std::wstring collect;
    auto add = [&](bool on, const wchar_t* what) { if (on) collect += (collect.empty() ? L"" : L", ") + std::wstring(what); };
    add(g_captureMemory, g_selftest ? L"memory image (SELF-TEST, synthetic)"
                         : g_driverMode ? L"memory image (WinPmem driver)"
                                        : L"memory image (driverless, experimental)");
    add(g_collectPagefile, L"pagefile.sys");
    add(g_collectHiberfil, L"hiberfil.sys");
    add(g_collectSwapfile, L"swapfile.sys");
    g_log.Line(std::wstring(L"==== RAMstain ") + kVersionStr + L" run started ====\n"
               L"Time:        " + FormatUtcAndLocal(FILETIME{}) + L"\n"
               L"Host:        " + GetComputerName() + L"\n"
               L"OS:          " + GetOsVersionString() + L"\n"
               L"User:        " + user + (elevated ? L" (elevated)" : L" (not elevated)") + L"\n"
               L"Process:     PID " + std::to_wstring(GetCurrentProcessId()) + L"\n"
               L"Command:     " + GetCommandLineW() + L"\n" +
               CaseDetailsLines() +
               L"Output:      " + path + L"\n"
               L"Collect:     " + collect + L"\n"
               L"Split:       " + (g_splitBytes ? FormatGB(g_splitBytes) + L" parts" : std::wstring(L"none")) + L"\n"
               L"Free space:  " + (freeBytes ? FormatGB(freeBytes) : std::wstring(L"unknown")) +
               L" on the target volume");
}

// The run's outcome, results and hashes, then close the log.
static void LogRunEnd(const CaptureResult* r) {
    std::wstring m = L"Run finished after " + FormatDuration(r->seconds) + L"\n";
    if (!g_captureMemory)
        m += L"Memory image: not requested\n";
    else if (r->ok) {
        m += std::wstring(L"Memory image: ") +
             (r->cancelled ? L"stopped by user (partial)" : r->hashStopped ? L"complete, hash skipped (stopped)"
                                                                            : L"complete") +
             L", " + std::to_wstring(r->bytesWritten) + L" bytes\n";
        m += L"Image:       " + (r->parts.empty() ? r->path
                                                   : std::to_wstring(r->parts.size()) + L" parts, " +
                                                     r->parts.front().path + L" ...") + L"\n";
        m += L"SHA-256:     " + HashText(r, r->sha256) + L"\n";
        for (const SplitPart& part : r->parts)
            m += L"  " + part.path.substr(part.path.find_last_of(L"\\/") + 1) + L"  " +
                 (part.sha256.empty() ? std::wstring(L"not computed") : Utf8ToWide(part.sha256)) + L"\n";
        if (!r->method.empty()) m += L"Method:      " + r->method + L"\n";
    } else {
        m += L"Memory image: FAILED\nError:       " + (r->error.empty() ? std::wstring(L"unknown") : r->error) + L"\n";
    }
    for (const SysFileCapture& f : r->sysfiles)
        m += std::wstring(SysName(f.kind)) + L".sys: " +
             (!f.path.empty() ? std::to_wstring(f.bytes) + L" bytes, SHA-256 " + Utf8ToWide(f.sha256)
                              : L"not collected - " + f.error) + L"\n";
    m += L"==== run ended ====";
    g_log.Line(m);
    g_log.Close();
}

// "Run log:" line for the result dialogs (empty when no log could be written).
static std::wstring LogNote() {
    return g_log.Path().empty() ? std::wstring() : L"\nRun log:\n" + g_log.Path() + L"\n";
}

static void OnCapture() {
    if (g_capturing) return;

    std::wstring path = GetTextW(g_editPath);
    TrimRight(path);
    if (path.empty()) {
        ShowSubWindow(0, L"RAMstain", L"Please choose where to save the memory dump.",
                      L"OK", L"", L"", 460, 200);
        return;
    }

    // If the user typed a directory, append a default file name.
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        if (path.back() != L'\\' && path.back() != L'/') path += L"\\";
        path += DefaultDumpName();
        SetTextW(g_editPath, path);
    }

    // Case details: one line each (line breaks and tabs become spaces).
    auto field = [](HWND h) {
        std::wstring t = GetTextW(h);
        for (wchar_t& c : t) if (c == L'\r' || c == L'\n' || c == L'\t') c = L' ';
        TrimRight(t);
        size_t b = t.find_first_not_of(L' ');
        return b == std::wstring::npos ? std::wstring() : t.substr(b);
    };
    g_caseNumber = field(g_editCase);
    g_caseExaminer = field(g_editExaminer);
    g_caseNotes = field(g_editNotes);

    // What to collect. A self-test always writes its synthetic image and
    // never collects system files.
    g_captureMemory = g_selftest ||
        (SendMessageW(g_chkMemory, BM_GETCHECK, 0, 0) == BST_CHECKED);
    g_collectPagefile = !g_selftest &&
        (SendMessageW(g_chkPagefile, BM_GETCHECK, 0, 0) == BST_CHECKED);
    g_collectHiberfil = !g_selftest &&
        (SendMessageW(g_chkHiberfil, BM_GETCHECK, 0, 0) == BST_CHECKED);
    g_collectSwapfile = !g_selftest &&
        (SendMessageW(g_chkSwapfile, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool wantFiles = g_collectPagefile || g_collectHiberfil || g_collectSwapfile;
    if (!g_captureMemory && !wantFiles) {
        ShowSubWindow(0, L"Nothing to collect",
                      L"Tick at least one of Memory image, Pagefile, Hibernation file or Swapfile.",
                      L"OK", L"", L"", 460, 200);
        return;
    }

    // Driver mode (default): the checkbox, initialised from the command line.
    g_driverMode = (g_captureMemory && !g_selftest &&
                    (SendMessageW(g_chkDriver, BM_GETCHECK, 0, 0) == BST_CHECKED));
    std::wstring imagerProblem = g_driverMode ? CheckImagerAvailable() : L"";
    if (!imagerProblem.empty()) {
        // No imager available. Let the user either fall back to driverless or cancel.
        int r = ShowSubWindow(0, L"WinPmem imager not found",
            imagerProblem + L"\n\n"
            L"You can try the experimental driverless method instead, but it is "
            L"not a documented Windows API and is expected to fail.",
            L"OK", L"Try driverless", L"", 520, 360);
        if (r == 2) {
            g_driverMode = false;               // proceed driverless
            SendMessageW(g_chkDriver, BM_SETCHECK, BST_UNCHECKED, 0);
        } else {
            return;                              // cancel
        }
    }

    // Driverless: OpenProcess(PID -1) fails with error 87 on current Windows.
    // Find that out now rather than after a whole run (which still collects the
    // pagefile / hibernation file, then reports the memory image as failed).
    if (g_captureMemory && !g_driverMode && !g_selftest) {
        EnableSeDebugPrivilege();
        HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)-1);
        DWORD code = hp ? 0 : GetLastError();
        if (hp) CloseHandle(hp);
        if (code) {
            std::wstring why = L"The experimental driverless method does not work on this system "
                               L"(OpenProcess(PID -1) failed with error " + std::to_wstring(code) +
                               L"), so it cannot capture the memory image.";
            bool imagerOk = imagerProblem.empty() && CheckImagerAvailable().empty();
            if (imagerOk) {
                int r = ShowSubWindow(0, L"Driverless method unavailable",
                    why + L"\n\nUse the WinPmem driver (built into RAMstain) for this capture?",
                    L"Use WinPmem driver", L"Cancel", L"", 520, 260);
                if (r != 1) return;
                g_driverMode = true;
                SendMessageW(g_chkDriver, BM_SETCHECK, BST_CHECKED, 0);
            } else if (wantFiles) {
                int r = ShowSubWindow(0, L"Memory capture unavailable",
                    why + L" The WinPmem imager is not available either.\n\n"
                    L"Collect the selected system files only?",
                    L"Files only", L"Cancel", L"", 520, 260);
                if (r != 1) return;
                g_captureMemory = false;
                SendMessageW(g_chkMemory, BM_SETCHECK, BST_UNCHECKED, 0);
                UpdateMemoryOptions(false);
            } else {
                ShowSubWindow(0, L"Memory capture unavailable",
                    why + L" The WinPmem imager is not available either.",
                    L"OK", L"", L"", 520, 240);
                return;
            }
        }
    }

    // Split option: part size in MiB from the combo's item data (0 = no split).
    {
        int sel = (int)SendMessageW(g_cmbSplit, CB_GETCURSEL, 0, 0);
        LRESULT mb = (sel >= 0) ? SendMessageW(g_cmbSplit, CB_GETITEMDATA, sel, 0) : 0;
        g_splitBytes = (g_captureMemory && mb > 0 && mb != CB_ERR) ? (UINT64)mb * 1024 * 1024 : 0;
    }

    // Size of the requested system files, for the disk-space check below.
    // (These live on the system volume, but worst-case the target is the same
    // volume; summing them is a conservative estimate.)
    UINT64 sysBytes = 0;
    for (SysKind k : kSysKinds)
        if (SysWanted(k))
            for (const auto& s : SysFileSources(k)) if (FilePresent(s)) { sysBytes += GetFileBytes(s); break; }

    // Disk-space sanity check. Splitting needs room for one extra part while it
    // moves data out of the image (see SplitImage). sysBytes is the actual size
    // of any requested pagefile / hibernation file (already measured above).
    UINT64 needed = g_captureMemory ? (UINT64)(GetTotalRamGB() * 1024.0 * 1024.0 * 1024.0) : 0;
    if (g_selftest) needed = 512u * 1024 * 1024;
    UINT64 splitExtra = (g_splitBytes && g_splitBytes < needed) ? g_splitBytes : 0;
    UINT64 freeB = 0;
    if (GetVolumeFreeBytes(path, freeB) &&
        freeB < needed + splitExtra + sysBytes + (UINT64)(1024 * 1024 * 1024)) {
        std::wstring msg = L"Not enough free disk space.\n" +
                           (needed ? L"\nEstimated image size: " +
                                     std::to_wstring((int)(needed / (1024 * 1024 * 1024)) + 1) +
                                     L" GB" +
                                     (splitExtra ? L" (+ " + FormatGB(splitExtra) + L" working space for splitting)"
                                                 : std::wstring())
                                   : std::wstring()) +
                           (sysBytes ? L"\n"
                                      L"System files: " + FormatGB(sysBytes)
                                     : std::wstring()) +
                           L"\nFree space on target volume: " +
                           std::to_wstring((int)(freeB / (1024 * 1024 * 1024))) + L" GB";
        ShowSubWindow(0, L"Not enough disk space", msg, L"OK", L"", L"", 480, 240);
        return;
    }

    // One warning before we load a kernel driver (once per session).
    if (g_driverMode && !g_driverWarned && !g_auto) {
        int r = ShowSubWindow(0, L"Driver mode",
            L"Driver mode will:\n"
            L"  • write the built-in WinPmem imager to a protected temporary "
            L"folder (deleted when RAMstain closes)\n"
            L"  • temporarily load the signed WinPmem kernel driver\n"
            L"  • create and remove a temporary Windows driver service\n"
            L"  • capture the full physical memory into a new timestamped folder\n\n"
            L"RAMstain is already running as Administrator.\n\nContinue?",
            L"Capture with driver", L"Cancel", L"", 500, 300);
        g_driverWarned = true;
        if (r != 1) { g_driverMode = false; return; }
    }

    // Every capture goes into a new folder next to the chosen file,
    // <save folder>\RAMstain_<local timestamp>\<file name>, so runs never mix
    // or overwrite each other (hence no overwrite prompt). Named and created
    // here, after every confirmation, so the timestamp is the capture's start
    // and a cancelled capture leaves nothing behind. Missing parent folders
    // are created too.
    std::wstring runDir, outPath;
    {
        size_t sl = path.find_last_of(L"\\/");
        std::wstring saveDir = (sl == std::wstring::npos) ? GetExeDir() : path.substr(0, sl);
        std::wstring name = (sl == std::wstring::npos) ? path : path.substr(sl + 1);
        std::wstring stamp = L"RAMstain_" + MakeTimestamp();
        runDir = saveDir + L"\\" + stamp;
        for (int k = 2; GetFileAttributesW(runDir.c_str()) != INVALID_FILE_ATTRIBUTES; ++k)
            runDir = saveDir + L"\\" + stamp + L"_" + std::to_wstring(k);   // same second
        outPath = runDir + L"\\" + name;
        int mk = SHCreateDirectoryExW(nullptr, runDir.c_str(), nullptr);
        if (mk != ERROR_SUCCESS) {
            ShowSubWindow(0, L"Cannot create folder",
                          L"Could not create the capture folder:\n" + runDir +
                          L"\n\nError " + std::to_wstring(mk) + L". Choose another save location.",
                          L"OK", L"", L"", 480, 220);
            return;
        }
    }

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_capturing = true;
    g_phase = CapturePhase::Capturing;
    g_phaseTotal = 0;
    SetBusy(true);
    SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    SendMessageW(g_progress, PBM_SETPOS, 0, 0);
    if (g_selftest)
        UpdateStatus(L"Running self-test (synthetic source)...", C.accent);
    else if (!g_captureMemory)
        UpdateStatus(L"Collecting system files...", C.accent);
    else if (g_driverMode)
        UpdateStatus(L"Capturing via WinPmem driver...", C.accent);
    else
        UpdateStatus(L"Capturing physical memory...", C.accent);

    static CaptureResult s_res;
    s_res = CaptureResult();
    s_res.path = outPath;
    g_activeResult = &s_res;
    LogRunStart(outPath, freeB);
    if (g_auto) ConsoleOut(L"Capturing into " + runDir + L"\n");

    HANDLE th = CreateThread(nullptr, 0, CaptureThreadProc, &s_res, 0, nullptr);
    if (!th) {
        g_capturing = false;
        SetBusy(false);
        g_activeResult = nullptr;
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        std::wstring m = L"Failed to start capture thread (error " +
                         std::to_wstring(GetLastError()) + L").";
        ShowSubWindow(0, L"RAMstain", m, L"OK", L"", L"", 460, 200);
        return;
    }
    CloseHandle(th);
}

static bool StopRequested() {
    return g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0;
}

static void RequestStop() {
    g_log.Line(L"Stop requested by user");
    if (g_stopEvent) SetEvent(g_stopEvent);
    UpdateStatus(L"Stopping capture...", C.muted);
    EnableWindow(g_btnClose, FALSE);
}

// Close/Stop button: stops a running capture (the button reads "Stop" then),
// otherwise closes RAMstain.
static void OnCloseButton() {
    if (g_capturing) RequestStop();
    else DestroyWindow(g_hwnd);
}

// X / Alt+F4 / Esc while a capture is running: ask before stopping it.
static void OnCloseWhileCapturing() {
    if (g_phase == CapturePhase::Splitting) {
        // The image is complete; interrupting the split would scatter it
        // across files. Let it finish, then close.
        g_closeAfterStop = true;
        UpdateStatus(L"Finishing the split - RAMstain will close when it is done.", C.muted);
        return;
    }
    if (StopRequested()) {           // already stopping: just close when done
        g_closeAfterStop = true;
        return;
    }
    int r = ShowSubWindow(0, L"Capture in progress",
        L"A memory capture is still running.\n\n"
        L"If you close RAMstain now, the capture is stopped. The partial image "
        L"and its .meta file are kept, but no hashes are computed.\n\n"
        L"Stop the capture and close RAMstain?",
        L"Stop and close", L"Keep capturing", L"", 500, 270);
    if (r != 1) return;
    g_closeAfterStop = true;
    if (g_capturing) RequestStop();
}

// One-line-per-file summary of the pagefile / hibernation files collected in
// this run, for the completion dialog (empty string when none were requested).
static std::wstring SysFileSummary(const CaptureResult* r, const wchar_t* heading = L"Also collected:") {
    if (r->sysfiles.empty()) return std::wstring();
    std::wstring s = std::wstring(heading) + L"\n";
    for (const SysFileCapture& f : r->sysfiles) {
        std::wstring label = std::wstring(SysLabel(f.kind)) + L":";
        if (!f.path.empty()) {
            s += label + L" " + std::to_wstring(f.bytes / (1024 * 1024)) +
                 L" MB -> " + f.path + L"\n" +
                 L"    SHA-256: " + (f.sha256.empty() ? std::wstring(L"not computed")
                                                      : Utf8ToWide(f.sha256)) + L"\n";
        } else {
            s += label + L" " + (f.error.empty() ? L"not collected\n" : f.error + L"\n");
        }
    }
    s += L"Each has its own .meta sidecar.\n";
    return s;
}

// SHA-256 of every file this run produced, one "<hash>  <file name>" line
// each (sha256sum format, so `sha256sum -c` checks them in the output
// folder). Empty when nothing was hashed.
static std::wstring HashList(const CaptureResult* r) {
    auto name = [](const std::wstring& p) { return p.substr(p.find_last_of(L"\\/") + 1); };
    std::wstring s;
    if (!r->sha256.empty())
        s += Utf8ToWide(r->sha256) + L"  " + name(r->path) + L"\n";
    for (const SplitPart& part : r->parts)
        if (!part.sha256.empty())
            s += Utf8ToWide(part.sha256) + L"  " + name(part.path) + L"\n";
    for (const SysFileCapture& f : r->sysfiles)
        if (!f.path.empty() && !f.sha256.empty())
            s += Utf8ToWide(f.sha256) + L"  " + name(f.path) + L"\n";
    return s;
}

// True when at least one requested system file was actually copied to disk.
static bool HasCollectedSysFile(const CaptureResult* r) {
    for (const SysFileCapture& f : r->sysfiles)
        if (!f.path.empty()) return true;
    return false;
}

// --auto exit code: 0 = everything requested was collected (and the image
// hashed), 1 = something failed, was stopped, or is incomplete - including an
// image the imager reported an error for (errCode: "may be incomplete"). A
// system file that does not exist on this machine is not a failure.
static int AutoExitCode(const CaptureResult* r) {
    if (g_captureMemory && !(r->ok && !r->cancelled && !r->hashStopped && !r->sha256.empty() &&
                             r->splitError.empty() && r->errCode == 0))
        return 1;
    for (SysKind k : kSysKinds) {
        if (!SysWanted(k)) continue;
        bool fine = false;
        for (const SysFileCapture& f : r->sysfiles)
            if (f.kind == k && (!f.path.empty() || f.absent)) fine = true;
        if (!fine) return 1;
    }
    return 0;
}

static void OnCaptureFinished() {
    g_capturing = false;
    SetBusy(false);
    if (g_progress) SendMessageW(g_progress, PBM_SETPOS, 100, 0);

    CaptureResult* r = g_activeResult;
    g_activeResult = nullptr;
    if (r) LogRunEnd(r);
    // --auto: after the result is reported (by whichever path below), exit.
    struct AutoExit {
        const CaptureResult* r;
        ~AutoExit() {
            if (!g_auto) return;
            g_exitCode = r ? AutoExitCode(r) : 1;
            ConsoleOut(L"\nExit code " + std::to_wstring(g_exitCode) + L"\n");
            DestroyWindow(g_hwnd);
        }
    } autoExit{ r };
    if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
    if (g_closeAfterStop) {           // "Stop and close": files are written, exit
        g_closeAfterStop = false;
        DestroyWindow(g_hwnd);
        return;
    }
    if (!r) return;

    if (!g_captureMemory) {                       // system files only
        bool any = HasCollectedSysFile(r);
        std::wstring dir = r->path;
        size_t sl = dir.find_last_of(L"\\/");
        if (sl != std::wstring::npos) dir = dir.substr(0, sl);
        UpdateStatus(any ? L"Done - system files collected." : L"Collection failed.",
                     any ? C.ok : C.danger);
        ShowSubWindow(1, any ? L"Collection complete" : L"Collection failed",
                      SysFileSummary(r, L"System files (no memory image requested):") +
                      L"\nTime:   " + FormatDuration(r->seconds) + L"\n" + LogNote() +
                      L"\nStored locally. No data was transmitted anywhere.",
                      L"Close", any ? L"Open folder" : L"", any ? dir : L"", 560, 320,
                      HashList(r));
        return;
    }

    if (r->ok) {
        double mbps = (r->bytesWritten / 1024.0 / 1024.0) / (r->seconds > 0.0 ? r->seconds : 1.0);
        std::wstring msg = (r->cancelled ? L"Capture stopped by user (partial image, hashes not computed).\n\n"
                            : r->hashStopped ? L"Capture complete. Hashes skipped (stopped by user during hashing).\n\n"
                            : (g_selftest ? L"Self-test complete (synthetic data).\n\n"
                                          : L"Capture complete.\n\n"));
        if (r->parts.empty()) {
            msg += L"Image:  " + r->path + L"\n";
        } else {
            msg += L"Image:  split into " + std::to_wstring(r->parts.size()) + L" parts of up to " +
                   FormatGB(r->parts.front().bytes) + L"\n"
                   L"        " + r->parts.front().path + L"\n"
                   L"        ... " + r->parts.back().path + L"\n";
        }
        if (!r->splitError.empty())
            msg += L"Split:  INCOMPLETE - " + r->splitError + L"\n";
        msg += L"Size:   " + std::to_wstring(r->bytesWritten / (1024 * 1024)) +
               L" MB  (" + std::to_wstring(r->pagesWritten) + L" pages)\n";
        msg += L"Time:   " + FormatDuration(r->seconds) + L"\n";
        msg += L"Speed:  " + std::to_wstring((int)mbps) + L" MB/s\n";
        msg += L"SHA-256: " + HashText(r, r->sha256) + L"\n";
        if (!r->method.empty())
            msg += L"Method: " + r->method + L"\n";
        std::wstring sys = SysFileSummary(r);
        if (!sys.empty()) msg += L"\n" + sys;
        if (!r->metaPath.empty())
            msg += L"\nMetadata sidecar:\n" + r->metaPath + L"\n";
        msg += LogNote();
        if (!r->parts.empty())
            msg += L"\nThe hashes are of the whole image; per-part hashes are in the .meta file.\n";
        msg += L"\nStored locally. No data was transmitted anywhere.";
        std::wstring dir = r->path;
        size_t sl = dir.find_last_of(L"\\/");
        if (sl != std::wstring::npos) dir = dir.substr(0, sl);
        ShowSubWindow(1,
                      (r->cancelled ? L"Capture stopped" : L"Capture complete"),
                      msg, L"Close", L"Open folder", dir, 560, 380, HashList(r));
        UpdateStatus(L"Done - " + std::to_wstring(r->bytesWritten / (1024 * 1024)) +
                     L" MB written.", C.ok);
    } else {
        // The memory image failed, but a requested pagefile / hibernation file
        // may still have been collected - report that instead of a flat failure.
        if (HasCollectedSysFile(r)) {
            UpdateStatus(L"Memory capture failed; system file(s) collected.", C.danger);
            std::wstring dir = r->path;
            size_t sl = dir.find_last_of(L"\\/");
            if (sl != std::wstring::npos) dir = dir.substr(0, sl);
            // What was collected first; the (long) memory error after it.
            ShowSubWindow(1, L"System files collected; memory capture failed",
                          SysFileSummary(r, L"Collected:") +
                          L"\nThe memory image was not captured:\n" +
                          (r->error.empty() ? L"Memory capture failed." : r->error) + L"\n" + LogNote(),
                          L"Close", L"Open folder", dir, 560, 380, HashList(r));
            return;
        }
        UpdateStatus(L"Capture failed.", C.danger);
        ShowSubWindow(1, L"Capture failed",
                      (r->error.empty() ? L"Capture failed." : r->error) + L"\n" + LogNote(),
                      L"Close", L"", L"", 560, 380);
    }
}

// Third-party notice shown at the end of the Terms of Use: the embedded
// WinPmem imager is Apache 2.0, which requires shipping its license text.
static std::wstring ThirdPartyNotice() {
    std::wstring s =
        L"\n\n"
        L"THIRD-PARTY SOFTWARE\n"
        L"====================\n"
        L"\n"
        L"RAMstain includes the WinPmem memory imager, Copyright 2012 Michael Cohen "
        L"<scudette@gmail.com>, distributed by Velocidex "
        L"(https://github.com/Velocidex/WinPmem). WinPmem is licensed under the "
        L"Apache License, Version 2.0, reproduced below. It is not covered by "
        L"RAMstain's MIT License or these Terms; its own license applies to it.\n"
        L"\n";
    HRSRC hr = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_WINPMEM_LICENSE), RT_RCDATA);
    HGLOBAL hg = hr ? LoadResource(nullptr, hr) : nullptr;
    const char* p = hg ? (const char*)LockResource(hg) : nullptr;
    DWORD n = hr ? SizeofResource(nullptr, hr) : 0;
    if (p && n)
        s += Utf8ToWide(std::string(p, n));
    else
        s += L"(License text missing from this build: see "
             L"http://www.apache.org/licenses/LICENSE-2.0)";
    return s;
}

// "?" next to the Split drop-down: how to use / merge split parts. Commands
// use the file name currently in the save-path field so they can be copied.
static void OnSplitHelp() {
    std::wstring path = GetTextW(g_editPath);
    TrimRight(path);
    size_t sl = path.find_last_of(L"\\/");
    std::wstring name = (sl == std::wstring::npos) ? path : path.substr(sl + 1);
    StripExtensionInPlace(name);
    if (name.empty()) name = L"image";
    // Quote names with spaces for cmd / PowerShell / sh.
    auto q = [](const std::wstring& n) {
        return n.find(L' ') != std::wstring::npos ? L"\"" + n + L"\"" : n;
    };
    std::wstring p1 = q(name + L".001"), p2 = q(name + L".002"), p3 = q(name + L".003");
    std::wstring raw = q(name + L".raw"), meta = name + L".meta";

    std::wstring body =
        L"Split parts are plain slices of one image: " + name + L".001, " + name + L".002, ... "
        L"Joined in order, they are byte-for-byte identical to the original image.\n"
        L"\n"
        L"1. YOU MAY NOT NEED TO MERGE\n"
        L"FTK Imager, X-Ways Forensics and Autopsy open split images directly: select "
        L"the .001 file. Tools that need a single file (for example Volatility) need "
        L"the parts merged first.\n"
        L"\n"
        L"2. MERGE ON WINDOWS\n"
        L"In Command Prompt, in the folder with the parts, list every part in order:\n"
        L"\n"
        L"    copy /b " + p1 + L" + " + p2 + L" + " + p3 + L" " + raw + L"\n"
        L"\n"
        L"With many parts, this PowerShell command joins all of them in name order:\n"
        L"\n"
        L"    $o = [IO.File]::Create(\"$PWD\\" + name + L".raw\"); "
        L"Get-ChildItem '" + name + L".0?\?' | Sort-Object Name | ForEach-Object { "
        L"$i = [IO.File]::OpenRead($_.FullName); $i.CopyTo($o); $i.Close() }; $o.Close()\n"
        L"\n"
        L"Do not use a wildcard with copy (such as copy /b " + name + L".0* ...). On "
        L"FAT32/exFAT drives it can join the parts in the wrong order.\n"
        L"\n"
        L"3. MERGE ON LINUX / MACOS\n"
        L"\n"
        L"    cat " + q(name) + L".0?? > " + raw + L"\n"
        L"\n"
        L"(the shell sorts the names, so the order is correct)\n"
        L"\n"
        L"4. CHECK THE RESULT\n"
        L"\n"
        L"    certutil -hashfile " + raw + L" SHA256\n"
        L"\n"
        L"The results must match the \"SHA-256:\" line in " + meta +
        L". Each part's own SHA-256 is listed there too. (On Linux/macOS: "
        L"sha256sum.)\n"
        L"\n"
        L"Merging needs free space equal to the full image size.";
    ShowSubWindow(0, L"Merging split images", body, L"Close", L"", L"", 620, 500);
}

static void OnLegalDoc(int which) {
    switch (which) {
    case IDC_BTN_DISC:
        ShowSubWindow(0, L"RAMstain - Disclaimer",
                      Utf8ToWide(kLegalDisclaimer), L"Close", L"", L"", 620, 460);
        break;
    case IDC_BTN_PRIV:
        ShowSubWindow(0, L"RAMstain - Privacy Policy",
                      Utf8ToWide(kLegalPrivacy), L"Close", L"", L"", 620, 460);
        break;
    case IDC_BTN_TERMS:
        ShowSubWindow(0, L"RAMstain - Terms of Use",
                      Utf8ToWide(kLegalTerms) + ThirdPartyNotice(), L"Close", L"", L"", 620, 460);
        break;
    }
}

// ---------------------------------------------------------------------------
//  Drag-to-move from anywhere in the form (empty parent areas).
//
//  Manual drag: on a left-button-down that lands on the parent's own surface
//  (not on a child control), take mouse capture and move the window to follow
//  the cursor; release on button-up. Interactive children (edit, checkbox,
//  owner-drawn buttons, progress bar) consume their own mouse messages, so a
//  press on them is NOT a drag and keeps working normally. This covers the
//  header band, card surface, labels, status and footer gap - effectively the
//  whole non-control area of the form.
// ---------------------------------------------------------------------------
static POINT  g_dragCursor;  // screen coords at drag start
static POINT  g_dragWinPos;  // window top-left at drag start
static bool   g_dragging = false;

static void DragMoveWindow(HWND hwnd) {
    // Move the window by the same delta the cursor has moved since drag start
    // (g_dragCursor / g_dragWinPos were captured at WM_LBUTTONDOWN).
    POINT cur;
    GetCursorPos(&cur);
    SetWindowPos(hwnd, nullptr,
                 g_dragWinPos.x + (cur.x - g_dragCursor.x),
                 g_dragWinPos.y + (cur.y - g_dragCursor.y),
                 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

// ---------------------------------------------------------------------------
//  Main window procedure
// ---------------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        int dpi = GetDpiForWindow(hwnd);
        auto S = [dpi](int v) { return Sc(v, dpi); };
        auto f = [&](int px, LONG weight) {
            LOGFONTW lf;
            ZeroMemory(&lf, sizeof(lf));
            lf.lfHeight = -px;
            lf.lfWeight = weight;
            lf.lfCharSet = DEFAULT_CHARSET;
            lf.lfQuality = CLEARTYPE_QUALITY;
            lstrcpyW(lf.lfFaceName, L"Segoe UI");
            return CreateFontIndirectW(&lf);
        };
        g_fTitle = f(S(16), FW_SEMIBOLD);   // header name
        g_fBody  = f(S(12), FW_SEMIBOLD);   // info values, percentage, Capture button
        g_fLabel = f(S(10), FW_SEMIBOLD);   // small-caps section label
        g_fSmall = f(S(12), FW_NORMAL);     // controls, info labels, status
        g_fEdit  = f(S(12), FW_NORMAL);     // save-path field
        g_fText  = f(S(13), FW_NORMAL);     // dialog / document body text
        g_fFoot  = f(S(11), FW_NORMAL);     // header subtitle, footer
        HINSTANCE hInst = ((LPCREATESTRUCT)lp)->hInstance;
        const int W = kDesignW;

        // Keyboard: controls are created in Tab order. A text label created
        // right before a control gives that control its Alt+letter shortcut.
        // "SAVE &TO" label (Alt+T -> path field).
        g_lblSave = CreateWindowExW(0, L"STATIC", L"SAVE &TO",
                                    WS_CHILD | WS_VISIBLE | WS_GROUP | SS_LEFT | SS_CENTERIMAGE,
                                    S(kPad), S(58), S(200), S(14),
                                    hwnd, nullptr, hInst, nullptr);
        SendMessageW(g_lblSave, WM_SETFONT, (WPARAM)g_fLabel, TRUE);

        // Save path: borderless edit inside the white field drawn in DrawMain
        // (x 16..416, y 74..100), vertically centred.
        g_editPath = CreateWindowExW(0, L"EDIT", L"",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | ES_AUTOHSCROLL,
                                      S(kPad + 5), S(79), S(W - 2 * kPad - kBrowseW - 8 - 10), S(17),
                                      hwnd, (HMENU)IDC_EDIT_PATH, hInst, nullptr);
        SendMessageW(g_editPath, WM_SETFONT, (WPARAM)g_fEdit, TRUE);
        SetTextW(g_editPath, g_cliPath.empty() ? DefaultDumpPath() : g_cliPath);
        g_btnBrowse = MakeButton(hwnd, L"&Browse...", S(W - kPad - kBrowseW), S(74), S(kBrowseW), S(26),
                                 BtnStyle::Secondary, (HMENU)IDC_BTN_BROWSE, g_fSmall, dpi);

        // Case details (y 108 caption, fields y 124..150): optional Case number,
        // Examiner and Notes, written into every .meta sidecar and the run log.
        // Borderless edits inside white fields drawn in DrawMain (kCaseFields);
        // grey placeholder text names each one. "CAS&E" label: Alt+E -> Case.
        g_lblCase = CreateWindowExW(0, L"STATIC", L"CAS&E DETAILS (OPTIONAL)",
                                    WS_CHILD | WS_VISIBLE | WS_GROUP | SS_LEFT | SS_CENTERIMAGE,
                                    S(kPad), S(108), S(240), S(14),
                                    hwnd, nullptr, hInst, nullptr);
        SendMessageW(g_lblCase, WM_SETFONT, (WPARAM)g_fLabel, TRUE);
        {
            struct { HWND* h; const wchar_t* cue; const std::wstring* text; int limit; } kFields[] = {
                { &g_editCase,     L"Case number", &g_cliCase,     128 },
                { &g_editExaminer, L"Examiner",    &g_cliExaminer, 128 },
                { &g_editNotes,    L"Notes",       &g_cliNotes,    512 },
            };
            for (int f = 0; f < 3; ++f) {
                HWND h = CreateWindowExW(0, L"EDIT", kFields[f].text->c_str(),
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | ES_AUTOHSCROLL,
                                         S(kCaseFields[f].x + 5), S(129), S(kCaseFields[f].w - 10), S(17),
                                         hwnd, nullptr, hInst, nullptr);
                SendMessageW(h, WM_SETFONT, (WPARAM)g_fEdit, TRUE);
                SendMessageW(h, EM_LIMITTEXT, kFields[f].limit, 0);
                SendMessageW(h, EM_SETCUEBANNER, FALSE, (LPARAM)kFields[f].cue);
                *kFields[f].h = h;
            }
        }

        // Options row (y 214..238): split drop-down after the "Split" label,
        // driver checkbox in the second column.
        // Item data = part size in MiB (0 = no split). 4095 MiB instead of 4096
        // keeps each part under FAT32's 4 GiB file limit.
        // "Sp&lit" label (Alt+L -> drop-down).
        g_lblSplit = CreateWindowExW(0, L"STATIC", L"Sp&lit",
                                     WS_CHILD | WS_VISIBLE | WS_GROUP | SS_LEFT | SS_CENTERIMAGE,
                                     S(kPad), S(214), S(38), S(24),
                                     hwnd, nullptr, hInst, nullptr);
        SendMessageW(g_lblSplit, WM_SETFONT, (WPARAM)g_fSmall, TRUE);
        g_cmbSplit = CreateWindowExW(0, WC_COMBOBOXW, L"",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | WS_VSCROLL | CBS_DROPDOWNLIST,
                                     S(kPad + 40), S(214), S(180), S(220),
                                     hwnd, (HMENU)IDC_CMB_SPLIT, hInst, nullptr);
        SendMessageW(g_cmbSplit, WM_SETFONT, (WPARAM)g_fSmall, TRUE);
        {
            struct { UINT mb; const wchar_t* text; } kSplit[] = {
                { 0,     L"No split (one file)" },
                { 1024,  L"1 GB parts" },
                { 2048,  L"2 GB parts" },
                { 4095,  L"4 GB parts (FAT32-safe)" },
                { 8192,  L"8 GB parts" },
                { 16384, L"16 GB parts" },
            };
            int sel = 0;
            for (const auto& s : kSplit) {
                int i = (int)SendMessageW(g_cmbSplit, CB_ADDSTRING, 0, (LPARAM)s.text);
                SendMessageW(g_cmbSplit, CB_SETITEMDATA, i, (LPARAM)s.mb);
                if (g_cliSplitMB && s.mb == g_cliSplitMB) sel = i;
            }
            if (g_cliSplitMB && sel == 0) {      // --split <MB> with a non-preset size
                std::wstring t = std::to_wstring(g_cliSplitMB) + L" MB parts";
                sel = (int)SendMessageW(g_cmbSplit, CB_ADDSTRING, 0, (LPARAM)t.c_str());
                SendMessageW(g_cmbSplit, CB_SETITEMDATA, sel, (LPARAM)g_cliSplitMB);
            }
            SendMessageW(g_cmbSplit, CB_SETCURSEL, sel, 0);
        }
        // Small round "?" right after the drop-down: how to merge split parts.
        g_btnSplitHelp = MakeButton(hwnd, L"?", S(kPad + 40 + 180 + 6), S(216), S(20), S(20),
                                    BtnStyle::Help, (HMENU)IDC_BTN_SPLITHELP, g_fBody, dpi);
        if (HWND tip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
                                       WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                       CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                                       hwnd, nullptr, hInst, nullptr)) {
            TTTOOLINFOW ti = { sizeof(ti) };
            ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
            ti.hwnd = hwnd;
            ti.uId = (UINT_PTR)g_btnSplitHelp;
            ti.lpszText = (LPWSTR)L"How to merge split parts";
            SendMessageW(tip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
        }

        // Default on (the driver is the primary method); --no-driver clears it.
        g_chkDriver = CreateWindowExW(0, L"BUTTON", L"Use WinPmem &driver (recommended)",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | BS_AUTOCHECKBOX,
                                      S(kCol2), S(215), S(W - kPad - kCol2), S(22),
                                      hwnd, (HMENU)IDC_CHK_DRIVER, hInst, nullptr);
        SendMessageW(g_chkDriver, WM_SETFONT, (WPARAM)g_fSmall, TRUE);
        SendMessageW(g_chkDriver, BM_SETCHECK,
                     (g_driverDefault && !g_selftest) ? BST_CHECKED : BST_UNCHECKED, 0);

        // Collect group: "COLLECT" caption (y 248, like "SAVE TO") over a white
        // panel drawn in DrawMain (y 264..296) with four checkboxes on a 120px
        // grid - Hibernation lines up with the driver checkbox (kCol2).
        // Unticking Memory image collects only the system files. The
        // checkboxes carry their own access keys (Alt+M, Alt+P, Alt+H, Alt+W);
        // the caption is decorative.
        g_lblCollect = CreateWindowExW(0, L"STATIC", L"COLLECT",
                                       WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE | SS_NOPREFIX,
                                       S(kPad), S(248), S(200), S(14),
                                       hwnd, nullptr, hInst, nullptr);
        SendMessageW(g_lblCollect, WM_SETFONT, (WPARAM)g_fLabel, TRUE);
        struct { HWND* h; const wchar_t* text; int id; bool on; } kCollect[] = {
            { &g_chkMemory,   L"&Memory image",    IDC_CHK_MEMORY,   !(g_cliNoMemory && !g_selftest) },
            { &g_chkPagefile, L"&Pagefile",        IDC_CHK_PAGEFILE, g_cliCollectPagefile && !g_selftest },
            { &g_chkHiberfil, L"&Hibernation file", IDC_CHK_HIBERFIL, g_cliCollectHiberfil && !g_selftest },
            { &g_chkSwapfile, L"S&wapfile",        IDC_CHK_SWAPFILE, g_cliCollectSwapfile && !g_selftest },
        };
        for (int c = 0; c < 4; ++c) {
            HWND h = CreateWindowExW(0, L"BUTTON", kCollect[c].text,
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | BS_AUTOCHECKBOX,
                                     S(kPad + 12 + 120 * c), S(269), S(c < 3 ? 112 : 104), S(22),
                                     hwnd, (HMENU)(INT_PTR)kCollect[c].id, hInst, nullptr);
            SendMessageW(h, WM_SETFONT, (WPARAM)g_fSmall, TRUE);
            SendMessageW(h, BM_SETCHECK, kCollect[c].on ? BST_CHECKED : BST_UNCHECKED, 0);
            *kCollect[c].h = h;
        }
        EnableWindow(g_chkMemory, !g_selftest);
        UpdateMemoryOptions(false);

        // Progress bar (y 312, 6px), percentage drawn to its right in DrawMain.
        g_progress = CreateWindowExW(0, PROGRESS_CLASSW, L"",
                                     WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                     S(kPad), S(312), S(W - 2 * kPad - 52), S(6),
                                     hwnd, (HMENU)IDC_PROGRESS, hInst, nullptr);
        SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessageW(g_progress, PBM_SETPOS, 0, 0);
        SendMessageW(g_progress, PBM_SETBARCOLOR, 0, (LPARAM)C.accent);

        // Action row (y 354..386): "Always on top" left, Capture + Close right.
        g_chkTop = CreateWindowExW(0, L"BUTTON", L"&Always on top",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | BS_AUTOCHECKBOX,
                                   S(kPad), S(360), S(130), S(20),
                                   hwnd, (HMENU)IDC_CHK_TOP, hInst, nullptr);
        SendMessageW(g_chkTop, WM_SETFONT, (WPARAM)g_fSmall, TRUE);
        SendMessageW(g_chkTop, BM_SETCHECK, BST_UNCHECKED, 0);
        // Capture before Close so Tab goes left to right.
        g_btnCapture = MakeButton(hwnd, L"&Capture", S(W - kPad - 84 - 8 - 104), S(354), S(104), S(32),
                                  BtnStyle::Primary, (HMENU)IDC_BTN_CAPTURE, g_fBody, dpi);
        g_btnClose = MakeButton(hwnd, L"Cl&ose", S(W - kPad - 84), S(354), S(84), S(32),
                                BtnStyle::Secondary, (HMENU)IDC_BTN_CLOSE, g_fSmall, dpi);

        // Footer links (y 398..426 strip).
        g_btnDisc = MakeButton(hwnd, L"D&isclaimer", S(12), S(kFooterY + 4), S(70), S(20),
                               BtnStyle::Link, (HMENU)IDC_BTN_DISC, g_fFoot, dpi);
        g_btnPriv = MakeButton(hwnd, L"Pri&vacy Policy", S(84), S(kFooterY + 4), S(88), S(20),
                               BtnStyle::Link, (HMENU)IDC_BTN_PRIV, g_fFoot, dpi);
        g_btnTerms = MakeButton(hwnd, L"Terms of &Use", S(174), S(kFooterY + 4), S(84), S(20),
                                BtnStyle::Link, (HMENU)IDC_BTN_TERMS, g_fFoot, dpi);

        g_hIcon = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_RAMSTAIN), IMAGE_ICON, S(24), S(24), 0);

        // "About RAMstain..." at the bottom of the title-bar icon menu.
        if (HMENU sys = GetSystemMenu(hwnd, FALSE)) {
            AppendMenuW(sys, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(sys, MF_STRING, IDM_ABOUT, L"About RAMstain...");
        }

        g_status = L"Ready.";
        g_statusColor = C.muted;
        return 0;
    }
    case WM_ACTIVATE:
        // Remember the focused control when the window loses activation (a
        // dialog opens, Alt+Tab) and give it focus back on return.
        if (LOWORD(wp) == WA_INACTIVE) {
            HWND f = GetFocus();
            if (f && IsChild(hwnd, f)) g_lastFocus = f;
        } else if (g_lastFocus && IsWindow(g_lastFocus) && IsWindowEnabled(g_lastFocus)) {
            SetFocus(g_lastFocus);
            return 0;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    case WM_TIMER:
        if (wp == kHdrAnimTimer) {
            if (GetTickCount() - g_hdrAnimStart > kHdrAnimRun + kHdrAnimFade)
                StopHeaderAnim(hwnd);
            RECT hr = { 0, 0, Sc(kDesignW, GetDpiForWindow(hwnd)), Sc(kHeaderH, GetDpiForWindow(hwnd)) };
            InvalidateRect(hwnd, &hr, FALSE);
            return 0;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == IDM_ABOUT) {
            ShowAbout();
            return 0;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    case WM_CTLCOLORSTATIC:
        // Checkboxes and labels sit on the grey body background, not on white boxes.
        if ((HWND)lp == g_chkMemory || (HWND)lp == g_chkPagefile ||
            (HWND)lp == g_chkHiberfil || (HWND)lp == g_chkSwapfile) {
            SetBkColor((HDC)wp, C.white);            // inside the Collect panel
            SetTextColor((HDC)wp, C.secText);
            return (LRESULT)g_brWhite;
        }
        if ((HWND)lp == g_chkTop || (HWND)lp == g_chkDriver) {
            SetBkColor((HDC)wp, C.bg);
            SetTextColor((HDC)wp, C.secText);
            return (LRESULT)g_brBg;
        }
        if ((HWND)lp == g_lblSave || (HWND)lp == g_lblSplit || (HWND)lp == g_lblCollect ||
            (HWND)lp == g_lblCase) {
            SetBkColor((HDC)wp, C.bg);
            SetTextColor((HDC)wp, ((HWND)lp == g_lblSave || (HWND)lp == g_lblCollect || (HWND)lp == g_lblCase)
                                     ? C.label : C.muted);
            return (LRESULT)g_brBg;
        }
        [[fallthrough]];
    case WM_CTLCOLOREDIT:
        SetBkColor((HDC)wp, C.white);
        return (LRESULT)g_brWhite;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        HDC mem = CreateCompatibleDC(hdc);
        HBITMAP bmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
        HBITMAP oldb = (HBITMAP)SelectObject(mem, bmp);
        DrawMain(mem, hwnd);
        BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
        SelectObject(mem, oldb);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DRAWITEM:
        if (((LPDRAWITEMSTRUCT)lp)->CtlType == DT_BUTTON) { PaintOwnerButton((LPDRAWITEMSTRUCT)lp); return TRUE; }
        return 0;
    case WM_COMMAND: {
        switch (LOWORD(wp)) {
        case IDC_BTN_BROWSE:  OnBrowse();  return 0;
        case IDC_BTN_CAPTURE: OnCapture(); return 0;
        case IDC_BTN_CLOSE:   OnCloseButton(); return 0;
        case IDC_BTN_DISC:    OnLegalDoc(IDC_BTN_DISC); return 0;
        case IDC_BTN_PRIV:    OnLegalDoc(IDC_BTN_PRIV); return 0;
        case IDC_BTN_TERMS:   OnLegalDoc(IDC_BTN_TERMS); return 0;
        case IDC_CHK_TOP: {
            g_topmost = (SendMessageW((HWND)lp, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SetWindowPos(hwnd, g_topmost ? HWND_TOPMOST : HWND_NOTOPMOST,
                         0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            return 0;
        }
        case IDC_BTN_SPLITHELP: OnSplitHelp(); return 0;
        case IDC_CHK_MEMORY:
            UpdateMemoryOptions(g_capturing);
            return 0;
        case IDC_CHK_DRIVER:
            // Just reflect the checkbox into g_driverMode; OnCapture is the only
            // consumer and it re-reads this each time.
            return 0;
        case IDOK: {
            // Enter (from the keyboard manager) when the focused control is not
            // itself a push button: press the focused owner-drawn button, if
            // any. Enter never closes the app or starts a capture on its own.
            HWND f = GetFocus();
            if (f && g_btns.count(f) && IsWindowEnabled(f))
                SendMessageW(f, BM_CLICK, 0, 0);
            return 0;
        }
        case IDCANCEL:        // Esc: same as X - warn if a capture is running
            if (g_capturing) OnCloseWhileCapturing(); else OnCloseButton();
            return 0;
        }
        return 0;
    }
    case WM_LBUTTONDOWN:
        // Drag the window when the press lands on the parent's own (empty)
        // area. Child controls (edit, checkbox, buttons, progress bar) consume
        // their own WM_LBUTTONDOWN, so this only fires for blank space - the
        // header band, card surface, labels, status and footer gap.
        SetFocus(hwnd);   // clicking empty space leaves the path field, like most apps
        GetCursorPos(&g_dragCursor);
        {
            RECT wr;
            GetWindowRect(hwnd, &wr);
            g_dragWinPos.x = wr.left;
            g_dragWinPos.y = wr.top;
        }
        g_dragging = true;
        SetCapture(hwnd);
        return 0;
    case WM_MOUSEMOVE:
        if (g_dragging)
            DragMoveWindow(hwnd);
        return 0;
    case WM_LBUTTONUP:
        if (g_dragging) {
            g_dragging = false;
            ReleaseCapture();
        }
        return 0;
    case WM_CAPTURECHANGED:
        // Capture taken away mid-drag (Alt-Tab, a dialog, another window
        // grabbing the mouse): end the drag, otherwise g_dragging stays set
        // and the window would follow the mouse on the next move.
        g_dragging = false;
        return 0;
    case WM_APP_PHASE:
        g_phase = (CapturePhase)wp;
        g_phaseTotal = (UINT64)lp;
        // Splitting cannot be stopped (see SplitImage); SetBusy(false) re-enables.
        if (g_phase == CapturePhase::Splitting) EnableWindow(g_btnClose, FALSE);
        return 0;
    case WM_APP_PROGRESS: {
        SendMessageW(g_progress, PBM_SETPOS, (WPARAM)wp, 0);
        // Status line: what is happening plus "<done> of <total>". Ignore late
        // progress after Stop was pressed so "Stopping capture..." stays visible.
        UINT64 done = (UINT64)lp;
        bool stopping = g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0;
        if (g_capturing && (!stopping || g_phase == CapturePhase::Splitting) &&
            !(g_closeAfterStop && g_phase == CapturePhase::Splitting)) {
            std::wstring s;
            if (g_phase == CapturePhase::Collecting)
                s = L"Collecting pagefile / hibernation file...";
            else if (g_phase == CapturePhase::Splitting)
                s = L"Splitting image into parts...";
            else if (g_phase == CapturePhase::Hashing)
                s = L"Computing SHA-256...";
            else if (g_selftest)
                s = L"Running self-test (synthetic source)...";
            else if (g_driverMode)
                s = L"Capturing via WinPmem driver...";
            else
                s = L"Capturing physical memory...";
            if (done > 0) {
                s += L"  " + FormatGB(done);
                if (g_phaseTotal > 0)
                    s += (g_phase == CapturePhase::Capturing && g_driverMode ? L" of ~" : L" of ") +
                         FormatGB(g_phaseTotal);
            }
            UpdateStatus(s, C.accent);
        } else {
            InvalidateRect(hwnd, nullptr, FALSE); // repaint percent text
        }
        return 0;
    }
    case WM_APP_FINISHED:
        if (g_subHwnd) {              // a dialog is open: handle when it closes
            g_finishPending = true;
            return 0;
        }
        OnCaptureFinished();
        return 0;
    case WM_GETMINMAXINFO: {
        int dpi = GetDpiForWindow(hwnd);
        MINMAXINFO* mmi = (MINMAXINFO*)lp;
        // Fixed-size window. ptMinTrackSize uses the designed CLIENT size as a
        // floor (harmless). Do NOT cap ptMaxTrackSize at that small value -
        // the real window must be a little larger than the client to absorb the
        // DWM frame, and an over-tight max would clamp the post-creation
        // client-size correction in wWinMain.
        mmi->ptMinTrackSize.x = Sc(kDesignW, dpi);
        mmi->ptMinTrackSize.y = Sc(kDesignH, dpi);
        mmi->ptMaxTrackSize.x = 4000;
        mmi->ptMaxTrackSize.y = 4000;
        return 0;
    }
    case WM_CLOSE:
        if (g_capturing) {
            OnCloseWhileCapturing(); // warn first; may stop and close later
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (g_subHwnd && IsWindow(g_subHwnd)) DestroyWindow(g_subHwnd);
        PostQuitMessage(g_exitCode);
        return 0;
    case WM_ENDSESSION:
        // Logoff/shutdown can end the process without returning from the
        // message loop, so remove the extracted imager here as well.
        if (wp) CleanupDroppedImager();
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ---------------------------------------------------------------------------
//  Entry point
// ---------------------------------------------------------------------------
static void CreateThemeGfx() {
    g_brBg = CreateSolidBrush(C.bg);
    g_brHeader = CreateSolidBrush(C.header);
    g_brLine = CreateSolidBrush(RGB(226, 232, 240));
    g_brFooter = CreateSolidBrush(RGB(241, 245, 249));
    g_brWhite = CreateSolidBrush(C.white);
    g_penEditBorder = CreatePen(PS_SOLID, 1, RGB(203, 213, 225));
    g_penNull = (HPEN)GetStockObject(NULL_PEN);
}

static void DestroyThemeGfx() {
    if (g_brBg) DeleteObject(g_brBg);
    if (g_brHeader) DeleteObject(g_brHeader);
    if (g_brLine) DeleteObject(g_brLine);
    if (g_brFooter) DeleteObject(g_brFooter);
    if (g_brWhite) DeleteObject(g_brWhite);
    if (g_penEditBorder) DeleteObject(g_penEditBorder);
    for (HFONT f : { g_fTitle, g_fBody, g_fLabel, g_fSmall, g_fEdit, g_fText, g_fFoot })
        if (f) DeleteObject(f);
    if (g_hIcon) DestroyIcon(g_hIcon);
    if (g_hIconAbout) DestroyIcon(g_hIconAbout);
    if (g_fHdrAnim) DeleteObject(g_fHdrAnim);
}

// --help: the supported command line, from one table. Printed to the console
// when there is one to reach (output redirected to a file or pipe, or started
// from an elevated prompt, whose console an elevated GUI app can attach to);
// otherwise - e.g. a normal prompt, where Windows starts RAMstain elevated in
// a new process with no console - shown in a message box. `problem` (an
// unknown option) is printed first. Returns the process exit code.
static int ShowCommandLineHelp(const std::wstring& problem) {
    struct { const wchar_t* opt; const wchar_t* desc; } kOpts[] = {
        { L"\"<output.raw>\"",         L"Pre-fill the save path; each capture goes into a new RAMstain_<timestamp> folder there" },
        { L"--split <MB>",             L"Preselect the split part size in MB (0 = no split, 4095 = FAT32-safe 4 GB)" },
        { L"--driver [<imager.exe>]",  L"Use the WinPmem driver (the default); optionally an external imager" },
        { L"--no-driver",              L"Select the experimental driverless method" },
        { L"--pagefile",               L"Also collect pagefile.sys" },
        { L"--hiberfil",               L"Also collect hiberfil.sys" },
        { L"--swapfile",               L"Also collect swapfile.sys" },
        { L"--system-files",           L"Also collect pagefile.sys, hiberfil.sys and swapfile.sys" },
        { L"--no-memory",              L"No memory image: collect the selected system files only" },
        { L"--case \"<text>\"",         L"Case number (written into every .meta and the run log)" },
        { L"--examiner \"<name>\"",     L"Examiner name (likewise)" },
        { L"--notes \"<text>\"",        L"Notes (likewise)" },
        { L"--selftest [\"<out.raw>\"]", L"512 MB synthetic test capture (no real memory is read)" },
        { L"--auto",                   L"Unattended: start at once, no dialogs, print the result and exit" },
        { L"--verify <folder>",        L"Re-hash a capture folder (or a .meta file) against its .meta records" },
        { L"--help, -h, /?",           L"Show this help" },
    };
    std::wstring head = std::wstring(L"RAMstain ") + kVersionStr +
                        L" - offline physical memory capture for Windows\n\n";
    if (!problem.empty()) head = problem + L"\n\n" + head;
    const wchar_t* usage = L"Usage:  RAMstain.exe [\"<output.raw>\"] [options]\n\n";
    // Notes: hard-wrapped for an 80-column console; the message box wraps itself.
    const wchar_t* notes =
        L"Options only preselect the window's settings; the capture starts when you\n"
        L"click Capture. An external imager can also be set with the RAMSTAIN_WINPMEM\n"
        L"environment variable. RAMstain runs as Administrator.\n\n"
        L"Exit codes (--auto, --verify): 0 = all collected / all verified, 1 = failed or\n"
        L"incomplete, 2 = bad option or nothing to verify, 3 = could not start,\n"
        L"4 = RAMstain is already running.\n";
    const wchar_t* notesBox =
        L"Options only preselect the window's settings; the capture starts when you "
        L"click Capture.\n\nAn external imager can also be set with the RAMSTAIN_WINPMEM "
        L"environment variable. RAMstain runs as Administrator.\n\n"
        L"Exit codes (--auto, --verify): 0 = all collected / verified, 1 = failed or incomplete, "
        L"2 = bad option or nothing to verify, 3 = could not start, 4 = already running.";

    // Console form: aligned columns.
    std::wstring con = L"\n" + head + usage + L"Options:\n";
    for (const auto& o : kOpts) {
        std::wstring opt = o.opt;
        con += L"  " + opt + std::wstring(opt.size() < 26 ? 26 - opt.size() : 1, L' ') + o.desc + L"\n";
    }
    con += L"\n" + std::wstring(notes);

    // Console (redirected output or the parent's console), else a message box.
    if (ConsoleOut(con))
        return problem.empty() ? 0 : 2;
    // Message box: proportional font, so each option gets its own line.
    std::wstring box = head + usage;
    for (const auto& o : kOpts)
        box += std::wstring(o.opt) + L"\n        " + o.desc + L"\n";
    box += L"\n" + std::wstring(notesBox);
    MessageBoxW(nullptr, box.c_str(), L"RAMstain - command line",
                MB_OK | (problem.empty() ? MB_ICONINFORMATION : MB_ICONWARNING));
    return problem.empty() ? 0 : 2;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    // CLI: see ShowCommandLineHelp (RAMstain.exe --help) for the options.
    bool showHelp = false;
    std::wstring badOption, verifyTarget;
    {
        std::wstring cmd = GetCommandLineW();
        size_t i = 0;
        bool firstToken = true;
        std::vector<std::wstring> toks;
        while (i < cmd.size()) {
            while (i < cmd.size() && (cmd[i] == L' ' || cmd[i] == L'\t')) ++i;
            if (i >= cmd.size()) break;
            std::wstring tok;
            if (cmd[i] == L'"') {
                ++i;
                while (i < cmd.size() && cmd[i] != L'"') { tok.push_back(cmd[i]); ++i; }
                if (i < cmd.size()) ++i; // closing quote
            } else {
                while (i < cmd.size() && cmd[i] != L' ' && cmd[i] != L'\t') { tok.push_back(cmd[i]); ++i; }
            }
            if (firstToken) { firstToken = false; continue; } // program name
            toks.push_back(tok);
        }
        for (size_t k = 0; k < toks.size(); ++k) {
            const std::wstring& t = toks[k];
            if (_wcsicmp(t.c_str(), L"--help") == 0 || _wcsicmp(t.c_str(), L"-h") == 0 ||
                t == L"/?" || t == L"-?") {
                showHelp = true;
            } else if (_wcsicmp(t.c_str(), L"--auto") == 0) {
                g_auto = true;
            } else if (_wcsicmp(t.c_str(), L"--verify") == 0) {
                if (k + 1 < toks.size()) verifyTarget = toks[++k];
                else if (badOption.empty()) badOption = t + L" (needs a folder)";
            } else if (_wcsicmp(t.c_str(), L"--selftest") == 0) {
                g_selftest = true;
            } else if (_wcsicmp(t.c_str(), L"--driver-mode") == 0 ||
                       _wcsicmp(t.c_str(), L"--driver") == 0) {
                g_driverDefault = true;                   // driver mode (already the default)
                if (_wcsicmp(t.c_str(), L"--driver") == 0 &&
                    k + 1 < toks.size() && toks[k + 1][0] != L'-') {
                    g_driverPath = toks[k + 1];            // optional explicit imager path
                    ++k;
                }
            } else if (_wcsicmp(t.c_str(), L"--no-driver") == 0) {
                g_driverDefault = false;                   // start with driverless selected
            } else if (_wcsicmp(t.c_str(), L"--pagefile") == 0) {
                g_cliCollectPagefile = true;               // also collect pagefile.sys
            } else if (_wcsicmp(t.c_str(), L"--hiberfil") == 0) {
                g_cliCollectHiberfil = true;               // also collect hiberfil.sys
            } else if (_wcsicmp(t.c_str(), L"--swapfile") == 0) {
                g_cliCollectSwapfile = true;               // also collect swapfile.sys
            } else if (_wcsicmp(t.c_str(), L"--system-files") == 0) {
                g_cliCollectPagefile = true;
                g_cliCollectHiberfil = true;
                g_cliCollectSwapfile = true;               // all three
            } else if (_wcsicmp(t.c_str(), L"--case") == 0 && k + 1 < toks.size()) {
                g_cliCase = toks[++k];
            } else if (_wcsicmp(t.c_str(), L"--examiner") == 0 && k + 1 < toks.size()) {
                g_cliExaminer = toks[++k];
            } else if (_wcsicmp(t.c_str(), L"--notes") == 0 && k + 1 < toks.size()) {
                g_cliNotes = toks[++k];
            } else if (_wcsicmp(t.c_str(), L"--no-memory") == 0) {
                g_cliNoMemory = true;                      // system files only
            } else if (_wcsicmp(t.c_str(), L"--split") == 0 && k + 1 < toks.size()) {
                // --split <MB>: preselect a part size (0 = no split). Invalid
                // values are ignored and the drop-down keeps its default.
                const std::wstring& v = toks[++k];
                if (!v.empty() && wcsspn(v.c_str(), L"0123456789") == v.size() && v.size() <= 7)
                    g_cliSplitMB = (UINT)wcstoul(v.c_str(), nullptr, 10);
            } else if (t.size() > 1 && t[0] == L'-' && badOption.empty()) {
                badOption = t;                             // unknown option: not a save path
            } else if (g_cliPath.empty()) {
                g_cliPath = t;
                TrimRight(g_cliPath);
            }
        }
    }
    // Before the single-instance check, so --help works while RAMstain is open.
    if (showHelp || !badOption.empty())
        return ShowCommandLineHelp(badOption.empty() ? std::wstring()
                                                     : L"Unknown option: " + badOption);
    // --verify <folder>: no window; results to the console, else a message box.
    if (!verifyTarget.empty()) {
        std::wstring all;
        bool console = ConsoleOut(L"\n");
        int rc = VerifyCapture(verifyTarget, [&](const std::wstring& line) {
            all += line + L"\n";
            if (console) ConsoleOut(line + L"\n");
        });
        if (!console)
            MessageBoxW(nullptr, all.c_str(), L"RAMstain - verify",
                        MB_OK | (rc == 0 ? MB_ICONINFORMATION : MB_ICONWARNING));
        return rc;
    }

    // Single instance, machine-wide ("Global\" covers other logon sessions too):
    // two captures loading the WinPmem driver at once would conflict. The
    // handle is kept open for the life of the process; Windows releases it on
    // exit, including a crash.
    HANDLE instanceMutex = CreateMutexW(nullptr, FALSE, L"Global\\RAMstain.SingleInstance");
    if (instanceMutex && GetLastError() == ERROR_ALREADY_EXISTS && g_auto) {
        ConsoleOut(L"RAMstain is already running; only one copy can run at a time.\n");
        CloseHandle(instanceMutex);
        return 4;
    }
    if (instanceMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        // Bring the running copy (or its open dialog) to the front if it is in
        // this session; otherwise it is in another session - just say so.
        if (HWND other = FindWindowW(kWindowClass, nullptr)) {
            if (IsIconic(other)) ShowWindow(other, SW_RESTORE);
            SetForegroundWindow(GetLastActivePopup(other));
        } else {
            MessageBoxW(nullptr,
                        L"RAMstain is already running (possibly in another user session).\n\n"
                        L"Only one copy can run at a time.",
                        L"RAMstain", MB_OK | MB_ICONINFORMATION);
        }
        CloseHandle(instanceMutex);
        return 0;
    }

    // Remove imager folders left in %TEMP% by RAMstain instances that crashed.
    SweepStaleDropDirs();

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_PROGRESS_CLASS | ICC_BAR_CLASSES;   // progress bar, tooltips
    InitCommonControlsEx(&icc);

    CreateThemeGfx();

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = g_brBg;
    // Top-left title-bar icon (large for Alt-Tab, small for the caption).
    // The icon is compiled into the exe (RAMstain.ico, id IDI_RAMSTAIN=101), so
    // it can be loaded here at class-registration time.
    wc.hIcon   = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_RAMSTAIN), IMAGE_ICON, 32, 32, 0);
    wc.hIconSm = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_RAMSTAIN), IMAGE_ICON, 16, 16, 0);
    wc.lpszClassName = kWindowClass;
    if (!RegisterClassExW(&wc)) return 1;

    WNDCLASSEXW ws;
    ZeroMemory(&ws, sizeof(ws));
    ws.cbSize = sizeof(ws);
    ws.style = CS_HREDRAW | CS_VREDRAW;
    ws.lpfnWndProc = SubWndProc;
    ws.hInstance = hInstance;
    ws.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    ws.hbrBackground = g_brBg;
    // Same title-bar icon as the main window (Disclaimer, About, results, ...).
    ws.hIcon   = wc.hIcon;
    ws.hIconSm = wc.hIconSm;
    ws.lpszClassName = kSubClass;
    if (!RegisterClassExW(&ws)) return 1;

    // Fixed-size main window (kDesignW x kDesignH CLIENT @ 96dpi).
    // AdjustWindowRect under-counts the DWM invisible border on Win10/11, so
    // after creating we measure the real client size and nudge the window by
    // the delta to force the exact client size our layout is designed for.
    int dpi = GetDpiForSystem();
    const int kClientW = Sc(kDesignW, dpi);
    const int kClientH = Sc(kDesignH, dpi);
    RECT rc = { 0, 0, kClientW, kClientH };
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX, FALSE);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    g_hwnd = CreateWindowExW(0, kWindowClass,
                             L"RAMstain - Physical Memory Capture",
                             // WS_CLIPCHILDREN: the window's own full repaint (e.g.
                             // every status-line update) must not paint over its
                             // child controls, which would then stay hidden.
                             (WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX) | WS_CLIPCHILDREN,
                             x, y, w, h, nullptr, nullptr, hInstance, nullptr);
    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    // Force exact client size (corrects the DWM border under-count). Done after
    // ShowWindow so the final frame thickness is known.
    ForceClientSize(g_hwnd, kClientW, kClientH, true);
    // Always show access-key underlines and focus rings (Windows otherwise
    // hides them until Alt is pressed), then start with focus on Capture.
    SendMessageW(g_hwnd, WM_CHANGEUISTATE, MAKEWPARAM(UIS_CLEAR, UISF_HIDEACCEL | UISF_HIDEFOCUS), 0);
    SetFocus(g_btnCapture);
    UpdateWindow(g_hwnd);

    // --auto: start now. If the capture cannot start (a check failed - the
    // reason was printed), exit with 3; otherwise OnCaptureFinished exits.
    if (g_auto) {
        ConsoleOut(std::wstring(L"\nRAMstain ") + kVersionStr + L" - unattended capture\n");
        OnCapture();
        if (!g_capturing) {
            g_exitCode = 3;
            ConsoleOut(L"Capture did not start. Exit code 3\n");
            DestroyWindow(g_hwnd);
        }
    }

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        // Esc anywhere in the main window = quit (IDCANCEL: warns first if a
        // capture is running). A plain message loop never turns Esc into
        // IDCANCEL by itself, so do it here. Leave Esc alone while the Split
        // drop-down list is open - there it just closes the list.
        if (m.message == WM_KEYDOWN && m.wParam == VK_ESCAPE &&
            (m.hwnd == g_hwnd || IsChild(g_hwnd, m.hwnd)) &&
            !SendMessageW(g_cmbSplit, CB_GETDROPPEDSTATE, 0, 0)) {
            SendMessageW(g_hwnd, WM_COMMAND, IDCANCEL, 0);
            continue;
        }
        // Key history (idle only; not while typing in the path field or
        // changing the Split selection).
        if (m.message == WM_KEYDOWN && !g_capturing &&
            m.hwnd != g_editPath && m.hwnd != g_cmbSplit && m.hwnd != g_editCase &&
            m.hwnd != g_editExaminer && m.hwnd != g_editNotes &&
            (m.hwnd == g_hwnd || IsChild(g_hwnd, m.hwnd)) &&
            KeyRingMatch(m.wParam))
            StartHeaderAnim(g_hwnd);
        // F1: About.
        if (m.message == WM_KEYDOWN && m.wParam == VK_F1 &&
            (m.hwnd == g_hwnd || IsChild(g_hwnd, m.hwnd))) {
            ShowAbout();
            continue;
        }
        // Alt+access key of a checkbox: focus AND toggle it. (The keyboard
        // manager below only moves focus to a checkbox for its access key.)
        if (m.message == WM_SYSCHAR && (m.hwnd == g_hwnd || IsChild(g_hwnd, m.hwnd))) {
            HWND hit = nullptr;
            for (HWND c : { g_chkTop, g_chkDriver, g_chkMemory, g_chkPagefile, g_chkHiberfil, g_chkSwapfile }) {
                wchar_t t[128] = L"";
                GetWindowTextW(c, t, 128);
                const wchar_t* amp = wcschr(t, L'&');
                if (amp && amp[1] && towlower(amp[1]) == towlower((wchar_t)m.wParam) &&
                    IsWindowEnabled(c) && IsWindowVisible(c))
                    hit = c;
            }
            if (hit) {
                // Toggle explicitly and notify like a click would (BM_CLICK is
                // unreliable when the window is not the foreground window).
                SetFocus(hit);
                bool on = SendMessageW(hit, BM_GETCHECK, 0, 0) == BST_CHECKED;
                SendMessageW(hit, BM_SETCHECK, on ? BST_UNCHECKED : BST_CHECKED, 0);
                SendMessageW(g_hwnd, WM_COMMAND,
                             MAKEWPARAM(GetDlgCtrlID(hit), BN_CLICKED), (LPARAM)hit);
                continue;
            }
        }
        // Keyboard manager: Tab/Shift+Tab, Space, Enter, Alt+access keys.
        // Plain typed characters bypass it, so a letter alone never acts as an
        // access key (only Alt+letter does) - e.g. typing B on a focused button
        // must not open Browse.
        bool plainChar = (m.message == WM_CHAR && m.wParam >= 0x20);
        if (!plainChar && IsDialogMessageW(g_hwnd, &m))
            continue;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    CleanupDroppedImager();   // delete the extracted WinPmem imager + its folder
    DestroyThemeGfx();
    return (int)m.wParam;
}
