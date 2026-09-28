// ============================================================================
//  RAMstain - Compact Physical Memory Capture (Win32, zero dependencies)
//
//  Captures physical RAM using the Win32 Physical Memory Handle API
//  (OpenProcess on PID -1 / PAGE_READ_MEMORY) - the same technique used by
//  WinPMEM's raw mode. No kernel driver, no service, no registration, no
//  account, no network. Offline by design.
//
//  Output:
//    <name>.raw   physical memory image, 4 KiB page-aligned
//    <name>.meta  capture metadata (host, OS, kernel, size, MD5)
//
//  UI: modern flat theme (dark header band, cards, rounded owner-drawn
//      buttons, themed progress bar), Disclaimer / Privacy / Terms dialogs.
//
//  CLI:
//    RAMstain.exe ["C:\path\to\dump.raw"]     pre-fill the save path
//    RAMstain.exe --selftest ["C:\path\out"]  synthetic 512 MiB pipeline test
//
//  Build: MSVC (Visual Studio 2022), x64, static CRT
// ============================================================================
#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#define _WIN32_IE 0x0700
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <commdlg.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <map>
#include <cstdio>
#include <cstdint>
#include "md5.h"
#include "legal.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

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

#define IDC_SUB_TEXT     2001
#define IDC_SUB_PRIMARY  2002
#define IDC_SUB_SECOND   2003
#define IDC_SUB_OK       2004

#define WM_APP_PROGRESS (WM_APP + 1)   // wParam = percent
#define WM_APP_FINISHED (WM_APP + 2)

static const wchar_t* kWindowClass = L"RAMstain.MainWindow";
static const wchar_t* kSubClass    = L"RAMstain.SubWindow";
static const wchar_t* kVersionStr  = L"1.0.0";

// ---------------------------------------------------------------------------
//  Theme (light, flat, modern)
// ---------------------------------------------------------------------------
struct Theme {
    COLORREF bg, header, headerSub, card, cardBorder, text, muted, label;
    COLORREF accent, accentHover, accentDown, secBorder, secText, secFill;
    COLORREF danger, dangerHover, dangerDown, ok, white, disabledFill, disabledText;
    Theme() {
        bg           = RGB(248, 250, 252);
        header       = RGB(15, 23, 42);
        headerSub    = RGB(148, 163, 184);
        card         = RGB(255, 255, 255);
        cardBorder   = RGB(226, 232, 240);
        text         = RGB(15, 23, 42);
        muted        = RGB(100, 116, 139);
        label        = RGB(100, 116, 139);
        accent       = RGB(37, 99, 235);
        accentHover  = RGB(29, 78, 216);
        accentDown   = RGB(23, 64, 142);
        secBorder    = RGB(203, 213, 225);
        secText      = RGB(30, 41, 59);
        secFill      = RGB(255, 255, 255);
        danger       = RGB(220, 38, 38);
        dangerHover  = RGB(190, 18, 18);
        dangerDown   = RGB(153, 27, 27);
        ok           = RGB(5, 150, 105);
        white        = RGB(255, 255, 255);
        disabledFill = RGB(241, 245, 249);
        disabledText = RGB(148, 163, 184);
    }
};
static Theme C;

static HBRUSH g_brBg = nullptr, g_brCard = nullptr, g_brHeader = nullptr, g_brWhite = nullptr;
static HPEN   g_penCardBorder = nullptr, g_penEditBorder = nullptr, g_penNull = nullptr;
static HFONT  g_fTitle = nullptr, g_fBody = nullptr, g_fLabel = nullptr, g_fSmall = nullptr, g_fEdit = nullptr;
static HICON  g_hIcon = nullptr;

static HWND   g_hwnd = nullptr;
static HWND   g_editPath, g_btnBrowse, g_btnCapture, g_btnClose, g_progress,
              g_btnDisc, g_btnPriv, g_btnTerms;
static HANDLE g_stopEvent = nullptr;
static bool   g_capturing = false;
static bool   g_selftest  = false;
static std::wstring g_cliPath;

static std::wstring g_status;        // status line text
static COLORREF     g_statusColor;   // status line color

enum class BtnStyle { Primary, Secondary, Danger, Link };
struct BtnState { BtnStyle style; bool hover; };
static std::map<HWND, BtnState> g_btns;

struct CaptureResult {
    bool      ok = false;
    bool      cancelled = false;
    UINT      errCode = 0;
    UINT64    pagesWritten = 0;
    UINT64    bytesWritten = 0;
    double    seconds = 0.0;
    std::wstring error;              // user-facing (empty on success)
    std::string  md5;
    std::wstring path;
    std::wstring metaPath;
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

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w;
    if (n > 0) { w.resize(n); MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n); }
    return w;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s;
    if (n > 0) { s.resize(n); WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr); }
    return s;
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
    _snwprintf_s(b, sizeof(b), _TRUNCATE, L"%04d%02d%02d_%02d%02d%02d",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}

static std::wstring DefaultDumpPath() {
    std::wstring p = GetExeDir() + L"\\RAMstain_" + MakeTimestamp() + L".raw";
    int k = 1;
    while (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES)
        p = GetExeDir() + L"\\RAMstain_" + MakeTimestamp() + L"_" + std::to_wstring(k++) + L".raw";
    return p;
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
    DWORD n = MAX_COMPUTERNAME_LENGTH;
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
    if (h > 0) _snwprintf_s(b, sizeof(b), _TRUNCATE, L"%dh %dm %ds", h, m, s);
    else if (m > 0) _snwprintf_s(b, sizeof(b), _TRUNCATE, L"%dm %ds", m, s);
    else _snwprintf_s(b, sizeof(b), _TRUNCATE, L"%ds", s);
    return b;
}

// Free space on the volume containing `path`.
static bool GetVolumeFreeBytes(const std::wstring& path, UINT64& freeBytes) {
    std::wstring root = path;
    size_t sl = root.find_last_of(L"\\/");
    if (sl != std::wstring::npos && (sl + 1) != root.size()) root = root.substr(0, sl + 1);
    if (root.size() == 2 && root[1] == L':') root.push_back(L'\\');
    ULARGE_INTEGER avail = {0}, total = {0}, totalFree = {0};
    if (GetDiskFreeSpaceExW(root.c_str(), &avail, &total, &totalFree)) {
        freeBytes = avail.QuadPart;
        return true;
    }
    return false;
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
                    L"Windows rejected physical-memory access.\n"
                    L"Error 87 (ERROR_INVALID_PARAMETER) on OpenProcess(physical memory).\n\n"
                    L"This system - " + os +
                    L" - blocks the driverless physical-memory API at the OS level "
                    L"(Windows 11 24H2/25H2 hardened the kernel against "
                    L"OpenProcess(PID -1), even for an elevated token with SeDebugPrivilege).\n\n"
                    L"On a standard Windows 10 or Windows 11 23H2 or earlier machine the "
                    L"same executable captures full physical RAM with no driver.\n\n"
                    L"Options on this machine:\n"
                    L"  1. Run RAMstain on a Windows 10 / 11 (<=23H2) system.\n"
                    L"  2. Use a kernel-driver method (e.g. WinPMEM with a signed "
                    L"driver, or DumpIt) - requires a reboot and a signed kernel "
                    L"driver to be installed.\n"
                    L"  3. Use a VM: boot this machine's disk in a VM and capture "
                    L"the VM's RAM (guest is then a non-hardened OS).";
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

    // Metadata gathered up front for the .meta sidecar.
    std::wstring hostName  = GetComputerName();
    std::wstring osVersion = GetOsVersionString();
    std::wstring kernelVer = GetKernelVersionString();
    std::wstring capTime   = MakeTimestamp();

    MD5 md5;
    std::vector<BYTE> buf(kChunkBytes);

    UINT64 offset = 0;
    bool   anyWritten = false;
    bool   aborted = false;

    while (true) {
        if (g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) {
            res->cancelled = true;
            break;
        }
        SIZE_T got = 0;
        if (selftest) {
            got = (SIZE_T)kChunkBytes;
            FillSynthetic(buf.data(), kChunkBytes, offset);
        } else if (!ReadProcessMemory(hPhys, (LPCVOID)(SIZE_T)offset, buf.data(),
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
        if (!WriteFile(hFile, buf.data(), (DWORD)got, &written, nullptr) ||
            written != (DWORD)got) {
            UINT code = GetLastError();
            res->errCode = code;
            res->error = L"WriteFile failed - error " + std::to_wstring(code) +
                         (code == ERROR_DISK_FULL ? L" (disk full)" : L"") +
                         L".\nCapture aborted.";
            aborted = true;
            break;
        }
        md5.Update(buf.data(), got);
        anyWritten = true;
        offset += got;
        res->bytesWritten = offset;
        res->pagesWritten = offset / kPageSize;

        int pct = (int)((double)offset / (double)neededBytes * 100.0);
        if (pct > 100) pct = 100;
        PostMessageW(g_hwnd, WM_APP_PROGRESS, (WPARAM)pct, 0);

        if (offset >= neededBytes) break;
    }

    std::string md5Hex = md5.Hex();
    cleanup();

    if (aborted) return;
    res->ok = res->bytesWritten > 0;
    res->md5 = md5Hex;

    // Write .meta sidecar next to the image.
    if (res->ok) {
        std::wstring metaPath = res->path;
        StripExtensionInPlace(metaPath);
        metaPath += L".meta";
        std::wstring meta =
            L"RAMstain capture metadata\n"
            L"=========================\n"
            L"Image:       " + res->path + L"\n" +
            L"Host:        " + hostName + L"\n" +
            L"OS:          " + osVersion + L"\n" +
            L"Kernel:      " + kernelVer + L"\n" +
            L"Captured:    " + capTime + L" (local time)\n" +
            L"Size:        " + std::to_wstring(res->bytesWritten) + L" bytes\n" +
            L"Pages:       " + std::to_wstring(res->pagesWritten) + L" x 4096 bytes\n" +
            L"MD5:         " + Utf8ToWide(md5Hex) + L"\n" +
            L"Tool:        RAMstain " + kVersionStr + L"\n" +
            (selftest ? L"Method:      SELF-TEST synthetic source (not a memory capture)\n"
                      : L"Method:      Win32 Physical Memory Handle API (no driver, no network)\n") +
            (res->cancelled ? L"Note:        Capture stopped by user (partial image)\n" : L"");
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
}

static void* CaptureThreadProc(void* arg) {
    CaptureResult* res = (CaptureResult*)arg;
    LARGE_INTEGER t0, t1, qf;
    QueryPerformanceCounter(&t0);
    double msPerTick = 0.0;
    if (QueryPerformanceFrequency(&qf) && qf.QuadPart > 0)
        msPerTick = 1000.0 / (double)qf.QuadPart;

    RunCapture(res, g_selftest);

    QueryPerformanceCounter(&t1);
    res->seconds = msPerTick > 0 ? ((double)(t1.QuadPart - t0.QuadPart) * msPerTick) / 1000.0
                                 : 0.0;
    PostMessageW(g_hwnd, WM_APP_FINISHED, 0, 0);
    return nullptr;
}

// ---------------------------------------------------------------------------
//  Owner-drawn buttons (rounded, themed)
// ---------------------------------------------------------------------------
static void DrawRoundRect(HDC dc, RECT r, int rad, HBRUSH fill, HPEN pen) {
    HBRUSH ob = (HBRUSH)SelectObject(dc, fill);
    HPEN op = (HPEN)SelectObject(dc, pen);
    RoundRect(dc, r.left, r.top, r.right - r.left, r.bottom - r.top, rad * 2, rad * 2);
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

    int r = Sc(7, dpi);
    if (st.style == BtnStyle::Link) {
        RECT fr = rc;
        fr.left -= 2; fr.top -= 2; fr.right += 2; fr.bottom += 2;
        FillRect(hdc, &fr, g_brBg);
    } else {
        COLORREF fill;
        if (disabled) fill = C.disabledFill;
        else if (st.style == BtnStyle::Primary)
            fill = pressed ? C.accentDown : (st.hover ? C.accentHover : C.accent);
        else if (st.style == BtnStyle::Danger)
            fill = pressed ? C.dangerDown : (st.hover ? C.dangerHover : C.danger);
        else
            fill = pressed ? RGB(241, 245, 249) : C.secFill;
        DrawRoundRect(hdc, rc, r, (HBRUSH)CreateSolidBrush(fill), g_penNull);
        if (!disabled && st.style == BtnStyle::Secondary) {
            COLORREF bcol = st.hover ? C.accent : C.secBorder;
            DrawRoundRect(hdc, rc, r, (HBRUSH)GetStockObject(NULL_BRUSH),
                          CreatePen(PS_SOLID, 1, bcol));
        }
    }

    COLORREF tcol;
    if (disabled) tcol = C.disabledText;
    else if (st.style == BtnStyle::Link) tcol = st.hover ? C.accentHover : C.accent;
    else if (st.style == BtnStyle::Primary || st.style == BtnStyle::Danger) tcol = C.white;
    else tcol = C.secText;
    SetTextColor(hdc, tcol);

    if (st.style == BtnStyle::Link) {
        RECT tr = rc;
        tr.left += Sc(4, dpi);
        DrawTextW(hdc, text, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        if (st.hover) {
            SIZE sz;
            GetTextExtentPoint32W(hdc, text, (int)wcslen(text), &sz);
            int uy = rc.top + (rc.bottom - rc.top) / 2 + sz.cy / 2 + Sc(2, dpi);
            int ux = tr.left;
            MoveToEx(hdc, ux, uy, nullptr);
            LineTo(hdc, ux + sz.cx, uy);
        }
    } else {
        DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
    SelectObject(hdc, old);
}

static HWND MakeButton(HWND parent, const wchar_t* text, int x, int y, int w, int h,
                       BtnStyle style, HMENU id, HFONT f, int dpi) {
    HWND b = CreateWindowExW(0, L"BUTTON", text,
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                             x, y, w, h, parent, id,
                             GetModuleHandleW(nullptr), nullptr);
    if (f) SendMessageW(b, WM_SETFONT, (WPARAM)f, TRUE);
    g_btns[b] = BtnState{style, false};
    (void)dpi;
    return b;
}

static void TrackHover(HWND hwnd, int x, int y) {
    POINT pt{ x, y };
    bool onLink = false;
    for (auto& kv : g_btns) {
        HWND b = kv.first;
        if (!IsWindow(b) || (GetParent(b) != hwnd)) continue;
        RECT r;
        GetWindowRect(b, &r);
        POINT p1{ r.left, r.top }, p2{ r.right, r.bottom };
        ScreenToClient(hwnd, &p1);
        ScreenToClient(hwnd, &p2);
        r.left = p1.x; r.top = p1.y; r.right = p2.x; r.bottom = p2.y;
        bool hov = PtInRect(&r, pt) != 0;
        if (hov != kv.second.hover) {
            kv.second.hover = hov;
            InvalidateRect(hwnd, &r, FALSE);
        }
        if (hov && kv.second.style == BtnStyle::Link) onLink = true;
    }
    SetCursor(onLink ? LoadCursorW(nullptr, IDC_HAND) : LoadCursorW(nullptr, IDC_ARROW));
}

// ---------------------------------------------------------------------------
//  Sub windows (legal docs, notes, result) - themed, modal
// ---------------------------------------------------------------------------
struct SubSpec {
    int         kind;     // 0 = doc/note (one button), 1 = result (up to two buttons)
    std::wstring title;
    std::wstring body;
    std::wstring primaryBtn;   // right button
    std::wstring secondBtn;    // left button (empty = none)
    std::wstring openDir;      // if non-empty, second button opens this folder
    int         w, h;
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

static LRESULT CALLBACK SubWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        int dpi = GetDpiForWindow(hwnd);
        int W = g_subSpec.w, H = g_subSpec.h;

        HWND edit = CreateWindowExW(0, L"EDIT", g_subSpec.body.c_str(),
                                    WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
                                    Sc(16, dpi), Sc(16, dpi), W - Sc(32, dpi),
                                    H - Sc(16, dpi) - Sc(72, dpi),
                                    hwnd, (HMENU)IDC_SUB_TEXT, GetModuleHandleW(nullptr), nullptr);
        SendMessageW(edit, WM_SETFONT, (WPARAM)g_fBody, TRUE);

        int by = H - Sc(56, dpi);
        int bh = Sc(34, dpi);
        HWND b1 = MakeButton(hwnd, g_subSpec.primaryBtn.c_str(),
                             W - Sc(16, dpi) - Sc(110, dpi), by, Sc(110, dpi), bh,
                             BtnStyle::Primary, (HMENU)IDC_SUB_PRIMARY, g_fSmall, dpi);
        if (!g_subSpec.secondBtn.empty()) {
            MakeButton(hwnd, g_subSpec.secondBtn.c_str(),
                       W - Sc(16, dpi) - Sc(110, dpi) - Sc(10, dpi) - Sc(130, dpi), by,
                       Sc(130, dpi), bh, BtnStyle::Secondary, (HMENU)IDC_SUB_SECOND, g_fSmall, dpi);
        }
        (void)b1;
        return 0;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
        SetTextColor((HDC)lp, C.text);
        SetBkColor((HDC)lp, C.white);
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
                          (HBRUSH)GetStockObject(NULL_BRUSH),
                          CreatePen(PS_SOLID, 1, C.secBorder));
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
            DestroyWindow(hwnd);
            return 0;
        case IDC_SUB_SECOND:
            g_subResult = 2;
            if (!g_subSpec.openDir.empty())
                ShellExecuteW(hwnd, L"open", g_subSpec.openDir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            DestroyWindow(hwnd);
            return 0;
        }
        return 0;
    }
    case WM_MOUSEMOVE:
        TrackHover(hwnd, GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lp;
        mmi->ptMinTrackSize.x = g_subSpec.w;
        mmi->ptMinTrackSize.y = g_subSpec.h;
        mmi->ptMaxTrackSize.x = 4000;
        mmi->ptMaxTrackSize.y = 4000;
        return 0;
    }
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (g_subHwnd == hwnd) g_subHwnd = nullptr;
        // NOTE: do NOT PostQuitMessage here - the main window owns the message loop.
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// Show a themed modal sub window (blocks until closed).
// Returns 1 if the primary button was pressed, 2 if the secondary.
static int ShowSubWindow(int kind, const wchar_t* title, const std::wstring& body,
                         const std::wstring& primaryBtn, const std::wstring& secondBtn,
                         const std::wstring& openDir, int w, int h) {
    g_subSpec = SubSpec{kind, std::wstring(title), body, primaryBtn, secondBtn, openDir, w, h};
    g_subResult = 1;
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    g_subHwnd = CreateWindowExW(0, kSubClass, title,
                                WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                0, 0, w, h, g_hwnd /* owner: stays above main */,
                                nullptr, hInst, nullptr);
    if (!g_subHwnd) return 1;
    ForceClientSize(g_subHwnd, w, h, false);  // same DWM-border correction as main
    if (g_hwnd) CenterOverParent(g_hwnd, g_subHwnd);
    SetForegroundWindow(g_subHwnd);
    while (IsWindow(g_subHwnd)) {
        MSG m;
        if (!GetMessageW(&m, nullptr, 0, 0)) break; // main window quit
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    g_subHwnd = nullptr;
    return g_subResult;
}

// ---------------------------------------------------------------------------
//  Main window painting
// ---------------------------------------------------------------------------
static void DrawMain(HDC dc, HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    int dpi = GetDpiForWindow(hwnd);
    int W = rc.right, H = rc.bottom;

    // Background
    FillRect(dc, &rc, g_brBg);

    // Header band
    RECT hr = { 0, 0, W, Sc(64, dpi) };
    FillRect(dc, &hr, g_brHeader);

    if (g_hIcon)
        DrawIconEx(dc, Sc(16, dpi), Sc(14, dpi), g_hIcon, Sc(36, dpi), Sc(36, dpi), 0, nullptr, DI_NORMAL);
    SetBkMode(dc, TRANSPARENT);
    HFONT old = (HFONT)SelectObject(dc, g_fTitle);
    SetTextColor(dc, C.white);
    RECT tr = { Sc(64, dpi), Sc(6, dpi), W, Sc(42, dpi) };
    DrawTextW(dc, L"RAMstain", -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    old = (HFONT)SelectObject(dc, g_fSmall);
    SetTextColor(dc, C.headerSub);
    RECT sr = { Sc(64, dpi), Sc(38, dpi), W, Sc(62, dpi) };
    std::wstring sub = g_selftest ? L"Physical Memory Capture  -  SELF-TEST"
                                  : L"Physical Memory Capture";
    DrawTextW(dc, sub.c_str(), -1, &sr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, g_fBody);

    // Card
    RECT card = { Sc(16, dpi), Sc(80, dpi), W - Sc(16, dpi), Sc(336, dpi) };
    DrawRoundRect(dc, card, Sc(10, dpi), g_brCard, g_penCardBorder);

    auto label = [&](int x, int y, const wchar_t* s) {
        HFONT of = (HFONT)SelectObject(dc, g_fLabel);
        SetTextColor(dc, C.label);
        RECT r = { x, y, x + Sc(300, dpi), y + Sc(16, dpi) };
        DrawTextW(dc, s, -1, &r, DT_LEFT | DT_TOP | DT_SINGLELINE);
        SelectObject(dc, of);
    };
    auto value = [&](int x, int y, const std::wstring& s, HFONT f = nullptr, COLORREF col = C.text) {
        HFONT of = (HFONT)SelectObject(dc, f ? f : g_fBody);
        SetTextColor(dc, col);
        RECT r = { x, y, x + Sc(280, dpi), y + Sc(22, dpi) };
        DrawTextW(dc, s.c_str(), -1, &r, DT_LEFT | DT_TOP | DT_SINGLELINE);
        SelectObject(dc, of);
    };

    // Save location
    label(Sc(32, dpi), Sc(96, dpi), L"SAVE LOCATION");
    RECT er = { Sc(32, dpi), Sc(116, dpi), Sc(484, dpi), Sc(148, dpi) };
    DrawRoundRect(dc, er, Sc(7, dpi), (HBRUSH)GetStockObject(NULL_BRUSH), g_penEditBorder);

    // System info grid
    double gb = GetTotalRamGB();
    std::wstring est = g_selftest ? L"512 MB (synthetic)"
                                  : (std::to_wstring((int)gb) + L" GB  -  4 KiB pages");
    int x1 = Sc(32, dpi), x2 = Sc(330, dpi);
    label(x1, Sc(168, dpi), L"PHYSICAL MEMORY");
    value(x1, Sc(184, dpi), std::to_wstring((int)gb) + L" GB");
    label(x1, Sc(212, dpi), L"ESTIMATED IMAGE");
    value(x1, Sc(228, dpi), est);
    label(x2, Sc(168, dpi), L"HOST");
    value(x2, Sc(184, dpi), GetComputerName());
    label(x2, Sc(212, dpi), L"OS");
    value(x2, Sc(228, dpi), GetOsVersionString());

    // Progress
    label(Sc(32, dpi), Sc(262, dpi), L"PROGRESS");
    int pr = 0;
    if (g_progress) {
        int val = (int)SendMessageW(g_progress, PBM_GETPOS, 0, 0);
        pr = val;
    }
    std::wstring pct = std::to_wstring(pr) + L"%";
    SetBkMode(dc, TRANSPARENT);
    HFONT of = (HFONT)SelectObject(dc, g_fBody);
    SetTextColor(dc, C.text);
    RECT prr = { W - Sc(80, dpi), Sc(272, dpi), W - Sc(32, dpi), Sc(292, dpi) };
    DrawTextW(dc, pct.c_str(), -1, &prr, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, of);

    // Status
    if (!g_status.empty()) {
        HFONT of2 = (HFONT)SelectObject(dc, g_fSmall);
        SetTextColor(dc, g_statusColor);
        RECT sr2 = { Sc(32, dpi), Sc(296, dpi), W - Sc(32, dpi), Sc(316, dpi) };
        DrawTextW(dc, g_status.c_str(), -1, &sr2, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(dc, of2);
    }

    // Footer
    {
        HFONT of3 = (HFONT)SelectObject(dc, g_fSmall);
        SetTextColor(dc, C.muted);
        RECT vr = { Sc(32, dpi), Sc(402, dpi), W - Sc(32, dpi), Sc(424, dpi) };
        DrawTextW(dc, (std::wstring(L"v") + kVersionStr + L"   offline - no data is transmitted").c_str(),
                  -1, &vr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(dc, of3);
    }
}

// ---------------------------------------------------------------------------
//  UI actions
// ---------------------------------------------------------------------------
static void UpdateStatus(const std::wstring& s, COLORREF col) {
    g_status = s;
    g_statusColor = col;
    if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
}

static void SetBusy(bool busy) {
    EnableWindow(g_editPath, !busy);
    EnableWindow(g_btnBrowse, !busy);
    EnableWindow(g_btnCapture, !busy);
    if (busy) {
        g_btns[g_btnClose] = BtnState{BtnStyle::Danger, false};
        SetWindowTextW(g_btnClose, L"Stop");
    } else {
        g_btns[g_btnClose] = BtnState{BtnStyle::Secondary, false};
        SetWindowTextW(g_btnClose, L"Close");
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
    std::wstring wb(path);
    if (wb.size() >= MAX_PATH) wb = DefaultDumpPath();
    ofn.lpstrFile = &wb[0];
    ofn.nMaxFile = (DWORD)wb.size();
    ofn.lpstrDefExt = L"raw";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetSaveFileNameW(&ofn))
        SetTextW(g_editPath, wb);
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
        path += L"\\RAMstain_" + MakeTimestamp() + L".raw";
        SetTextW(g_editPath, path);
    }

    // Confirm overwrite.
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        std::wstring q = L"\"" + path + L"\" already exists.\n\nOverwrite the existing file?";
        if (ShowSubWindow(0, L"Overwrite?", q, L"Overwrite", L"Cancel", L"", 480, 240) != 1)
            return;
    }

    // Disk-space sanity check.
    UINT64 needed = (UINT64)(GetTotalRamGB() * 1024.0 * 1024.0 * 1024.0);
    if (g_selftest) needed = 512u * 1024 * 1024;
    UINT64 freeB = 0;
    if (GetVolumeFreeBytes(path, freeB) && freeB < needed + (UINT64)(1024 * 1024 * 1024)) {
        std::wstring msg = L"Not enough free disk space.\n\n"
                           L"Estimated image size: " +
                           std::to_wstring((int)(needed / (1024 * 1024 * 1024)) + 1) +
                           L" GB\nFree space on target volume: " +
                           std::to_wstring((int)(freeB / (1024 * 1024 * 1024))) + L" GB";
        ShowSubWindow(0, L"Not enough disk space", msg, L"OK", L"", L"", 480, 240);
        return;
    }

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_capturing = true;
    SetBusy(true);
    SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    SendMessageW(g_progress, PBM_SETPOS, 0, 0);
    UpdateStatus(g_selftest ? L"Running self-test (synthetic source)..."
                            : L"Capturing physical memory...", C.accent);

    static CaptureResult s_res;
    s_res = CaptureResult();
    s_res.path = path;
    g_activeResult = &s_res;

    HANDLE th = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)CaptureThreadProc,
                             &s_res, 0, nullptr);
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

static void OnCloseButton() {
    if (g_capturing) {
        if (g_stopEvent) SetEvent(g_stopEvent);
        UpdateStatus(L"Stopping capture...", C.muted);
        EnableWindow(g_btnClose, FALSE);
    } else {
        DestroyWindow(g_hwnd);
    }
}

static void OnCaptureFinished() {
    g_capturing = false;
    SetBusy(false);
    if (g_progress) SendMessageW(g_progress, PBM_SETPOS, 100, 0);

    CaptureResult* r = g_activeResult;
    g_activeResult = nullptr;
    if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
    if (!r) return;

    if (r->ok) {
        double mbps = (r->bytesWritten / 1024.0 / 1024.0) / (r->seconds > 0.0 ? r->seconds : 1.0);
        std::wstring msg = (r->cancelled ? L"Capture stopped by user (partial image).\n\n"
                                         : (g_selftest ? L"Self-test complete (synthetic data).\n\n"
                                                       : L"Capture complete.\n\n"));
        msg += L"Image:  " + r->path + L"\n";
        msg += L"Size:   " + std::to_wstring(r->bytesWritten / (1024 * 1024)) +
               L" MB  (" + std::to_wstring(r->pagesWritten) + L" pages)\n";
        msg += L"Time:   " + FormatDuration(r->seconds) + L"\n";
        msg += L"Speed:  " + std::to_wstring((int)mbps) + L" MB/s\n";
        msg += L"MD5:    " + Utf8ToWide(r->md5) + L"\n";
        if (!r->metaPath.empty())
            msg += L"\nMetadata sidecar:\n" + r->metaPath + L"\n";
        msg += L"\nStored locally. No data was transmitted anywhere.";
        std::wstring dir = r->path;
        size_t sl = dir.find_last_of(L"\\/");
        if (sl != std::wstring::npos) dir = dir.substr(0, sl);
        ShowSubWindow(1,
                      (r->cancelled ? L"Capture stopped" : L"Capture complete"),
                      msg, L"Close", L"Open folder", dir, 560, 380);
        UpdateStatus(L"Done - " + std::to_wstring(r->bytesWritten / (1024 * 1024)) +
                     L" MB written.", C.ok);
    } else {
        UpdateStatus(L"Capture failed.", C.danger);
        ShowSubWindow(1, L"Capture failed",
                      r->error.empty() ? L"Capture failed." : r->error,
                      L"Close", L"", L"", 560, 380);
    }
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
                      Utf8ToWide(kLegalTerms), L"Close", L"", L"", 620, 460);
        break;
    }
}

// ---------------------------------------------------------------------------
//  Main window procedure
// ---------------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        int dpi = GetDpiForWindow(hwnd);
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
        g_fTitle = f(Sc(19, dpi), FW_SEMIBOLD);
        g_fBody  = f(Sc(14, dpi), FW_SEMIBOLD);
        g_fLabel = f(Sc(10, dpi), FW_SEMIBOLD);
        g_fSmall = f(Sc(12, dpi), FW_NORMAL);
        g_fEdit  = f(Sc(13, dpi), FW_NORMAL);
        HINSTANCE hInst = ((LPCREATESTRUCT)lp)->hInstance;

        // Save path edit (custom border drawn in WM_PAINT)
        g_editPath = CreateWindowExW(0, L"EDIT", L"",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                      Sc(33, dpi), Sc(117, dpi), Sc(450, dpi), Sc(30, dpi),
                                      hwnd, (HMENU)IDC_EDIT_PATH, hInst, nullptr);
        SendMessageW(g_editPath, WM_SETFONT, (WPARAM)g_fEdit, TRUE);
        SetTextW(g_editPath, g_cliPath.empty() ? DefaultDumpPath() : g_cliPath);

        // Buttons
        g_btnBrowse = MakeButton(hwnd, L"Browse...", Sc(492, dpi), Sc(116, dpi), Sc(96, dpi), Sc(32, dpi),
                                 BtnStyle::Secondary, (HMENU)IDC_BTN_BROWSE, g_fSmall, dpi);
        g_btnCapture = MakeButton(hwnd, L"Capture", Sc(32, dpi), Sc(352, dpi), Sc(150, dpi), Sc(38, dpi),
                                  BtnStyle::Primary, (HMENU)IDC_BTN_CAPTURE, g_fBody, dpi);
        g_btnClose = MakeButton(hwnd, L"Close", Sc(194, dpi), Sc(352, dpi), Sc(120, dpi), Sc(38, dpi),
                                BtnStyle::Secondary, (HMENU)IDC_BTN_CLOSE, g_fSmall, dpi);

        // Progress bar
        g_progress = CreateWindowExW(0, PROGRESS_CLASSW, L"",
                                     WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                     Sc(32, dpi), Sc(278, dpi), Sc(508, dpi), Sc(12, dpi),
                                     hwnd, (HMENU)IDC_PROGRESS, hInst, nullptr);
        SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessageW(g_progress, PBM_SETPOS, 0, 0);
        SendMessageW(g_progress, PBM_SETBARCOLOR, 0, (LPARAM)C.accent);

        // Footer links
        g_btnDisc = MakeButton(hwnd, L"Disclaimer", Sc(300, dpi), Sc(402, dpi), Sc(88, dpi), Sc(24, dpi),
                               BtnStyle::Link, (HMENU)IDC_BTN_DISC, g_fSmall, dpi);
        g_btnPriv = MakeButton(hwnd, L"Privacy Policy", Sc(394, dpi), Sc(402, dpi), Sc(106, dpi), Sc(24, dpi),
                               BtnStyle::Link, (HMENU)IDC_BTN_PRIV, g_fSmall, dpi);
        g_btnTerms = MakeButton(hwnd, L"Terms of Use", Sc(506, dpi), Sc(402, dpi), Sc(92, dpi), Sc(24, dpi),
                                BtnStyle::Link, (HMENU)IDC_BTN_TERMS, g_fSmall, dpi);

        g_hIcon = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(101), IMAGE_ICON, Sc(36, dpi), Sc(36, dpi), 0);
        g_status = L"Ready.";
        g_statusColor = C.muted;
        return 0;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
        SetBkColor((HDC)lp, C.white);
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
        case IDOK:
        case IDCANCEL:        OnCloseButton(); return 0;
        }
        return 0;
    }
    case WM_MOUSEMOVE:
        TrackHover(hwnd, GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
        return 0;
    case WM_APP_PROGRESS:
        SendMessageW(g_progress, PBM_SETPOS, (WPARAM)wp, 0);
        InvalidateRect(hwnd, nullptr, FALSE); // repaint percent text
        return 0;
    case WM_APP_FINISHED:
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
        mmi->ptMinTrackSize.x = Sc(620, dpi);
        mmi->ptMinTrackSize.y = Sc(432, dpi);
        mmi->ptMaxTrackSize.x = 4000;
        mmi->ptMaxTrackSize.y = 4000;
        return 0;
    }
    case WM_CLOSE:
        if (g_capturing) {
            OnCloseButton(); // starts a stop
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (g_subHwnd && IsWindow(g_subHwnd)) DestroyWindow(g_subHwnd);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ---------------------------------------------------------------------------
//  Entry point
// ---------------------------------------------------------------------------
static void CreateThemeGfx() {
    g_brBg = CreateSolidBrush(C.bg);
    g_brCard = CreateSolidBrush(C.card);
    g_brHeader = CreateSolidBrush(C.header);
    g_brWhite = CreateSolidBrush(C.white);
    g_penCardBorder = CreatePen(PS_SOLID, 1, C.cardBorder);
    g_penEditBorder = CreatePen(PS_SOLID, 1, RGB(203, 213, 225));
    g_penNull = (HPEN)GetStockObject(NULL_PEN);
}

static void DestroyThemeGfx() {
    if (g_brBg) DeleteObject(g_brBg);
    if (g_brCard) DeleteObject(g_brCard);
    if (g_brHeader) DeleteObject(g_brHeader);
    if (g_brWhite) DeleteObject(g_brWhite);
    if (g_penCardBorder) DeleteObject(g_penCardBorder);
    if (g_penEditBorder) DeleteObject(g_penEditBorder);
    for (HFONT f : { g_fTitle, g_fBody, g_fLabel, g_fSmall, g_fEdit })
        if (f) DeleteObject(f);
    if (g_hIcon) DestroyIcon(g_hIcon);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    // CLI: RAMstain.exe [--selftest] ["path"]
    {
        std::wstring cmd = GetCommandLineW();
        size_t i = 0;
        bool firstToken = true;
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
            if (_wcsicmp(tok.c_str(), L"--selftest") == 0) g_selftest = true;
            else if (g_cliPath.empty()) { g_cliPath = tok; TrimRight(g_cliPath); }
        }
    }

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_PROGRESS_CLASS;
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
    ws.lpszClassName = kSubClass;
    if (!RegisterClassExW(&ws)) return 1;

    // Fixed-size main window (620x432 CLIENT @ 96dpi).
    // AdjustWindowRect under-counts the DWM invisible border on Win10/11, so
    // after creating we measure the real client size and nudge the window by
    // the delta to force the exact client size our layout is designed for.
    int dpi = GetDpiForSystem();
    const int kClientW = Sc(620, dpi);
    const int kClientH = Sc(432, dpi);
    RECT rc = { 0, 0, kClientW, kClientH };
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX, FALSE);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    g_hwnd = CreateWindowExW(0, kWindowClass,
                             L"RAMstain - Physical Memory Capture",
                             WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
                             x, y, w, h, nullptr, nullptr, hInstance, nullptr);
    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    // Force exact client size (corrects the DWM border under-count). Done after
    // ShowWindow so the final frame thickness is known.
    ForceClientSize(g_hwnd, kClientW, kClientH, true);
    UpdateWindow(g_hwnd);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    DestroyThemeGfx();
    return (int)m.wParam;
}
