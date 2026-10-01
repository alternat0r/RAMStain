// Finding Windows-created memory dumps - see crash_dumps.h.
#include "crash_dumps.h"
#include <algorithm>
#include <cwctype>
#include <set>

namespace {

std::wstring Expand(const std::wstring& s) {
    wchar_t buf[2048] = L"";
    DWORD n = ExpandEnvironmentStringsW(s.c_str(), buf, _countof(buf));
    return (n > 0 && n <= _countof(buf)) ? std::wstring(buf) : s;
}

// A string value (REG_SZ / REG_EXPAND_SZ, expanded), or `fallback`.
std::wstring RegString(HKEY root, const wchar_t* subkey, const wchar_t* value, const std::wstring& fallback) {
    wchar_t buf[1024] = L"";
    DWORD cb = sizeof(buf);
    if (RegGetValueW(root, subkey, value, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
                     nullptr, buf, &cb) == ERROR_SUCCESS && buf[0])
        return Expand(buf);
    return fallback.empty() ? fallback : Expand(fallback);
}

std::wstring Lower(std::wstring s) {
    for (wchar_t& c : s) c = (wchar_t)towlower(c);
    return s;
}

bool IsDumpName(const std::wstring& name) {
    std::wstring n = Lower(name);
    for (const wchar_t* ext : { L".dmp", L".mdmp", L".hdmp" }) {
        size_t e = wcslen(ext);
        if (n.size() > e && n.compare(n.size() - e, e, ext) == 0) return true;
    }
    return false;
}

class Finder {
public:
    Finder(bool mini, bool sys, bool app, std::vector<std::wstring>* searched)
        : m_want{ mini, sys, app }, m_searched(searched) {}

    // Dump files in dir (and below it when recursive). In WER report folders,
    // a top-level "Kernel_*" report holds a kernel dump, anything else an app's.
    void Folder(const std::wstring& dir, DumpKind kind, bool recursive, bool werReports = false) {
        if (dir.empty() || !Wanted(kind, werReports)) return;
        Note(dir);                                    // recorded even when absent
        DWORD a = GetFileAttributesW(dir.c_str());
        if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY)) return;
        Walk(dir, kind, recursive, werReports, 0);
    }
    void File(const std::wstring& path, DumpKind kind) {
        if (path.empty() || !m_want[(int)kind]) return;
        Note(path);
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(path.c_str(), &fd);   // works on files locked by the OS
        if (h == INVALID_HANDLE_VALUE) return;
        FindClose(h);
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) Add(path, kind, fd);
    }
    std::vector<DumpSource> Take() {
        std::sort(m_out.begin(), m_out.end(),
                  [](const DumpSource& x, const DumpSource& y) { return _wcsicmp(x.path.c_str(), y.path.c_str()) < 0; });
        return std::move(m_out);
    }

private:
    bool Wanted(DumpKind kind, bool werReports) const {
        return werReports ? (m_want[(int)DumpKind::System] || m_want[(int)DumpKind::App]) : m_want[(int)kind];
    }
    void Note(const std::wstring& p) { if (m_searched) m_searched->push_back(p); }

    // werRoot: dir is a WER ReportArchive/ReportQueue folder, whose subfolders
    // are reports - "Kernel_*" ones hold kernel dumps, the rest app dumps.
    void Walk(const std::wstring& dir, DumpKind kind, bool recursive, bool werRoot, int depth) {
        if (depth > 8) return;
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileExW((dir + L"\\*").c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch,
                                    nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            std::wstring n = fd.cFileName;
            if (n == L"." || n == L"..") continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;   // no junction loops
            std::wstring full = dir + L"\\" + n;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!recursive) continue;
                DumpKind k = !werRoot ? kind
                           : (_wcsnicmp(n.c_str(), L"Kernel_", 7) == 0) ? DumpKind::System : DumpKind::App;
                if (m_want[(int)k]) Walk(full, k, recursive, false, depth + 1);
            } else if (IsDumpName(n) && m_want[(int)kind]) {
                Add(full, kind, fd);
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }

    void Add(const std::wstring& path, DumpKind kind, const WIN32_FIND_DATAW& fd) {
        if (!m_seen.insert(Lower(path)).second) return;   // same file via two locations
        DumpSource d;
        d.kind = kind;
        d.path = path;
        d.bytes = ((UINT64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        d.created = fd.ftCreationTime;
        d.modified = fd.ftLastWriteTime;
        m_out.push_back(d);
    }

    bool m_want[3];
    std::vector<std::wstring>* m_searched;
    std::set<std::wstring> m_seen;
    std::vector<DumpSource> m_out;
};

}  // namespace

const wchar_t* DumpKindName(DumpKind k) {
    return k == DumpKind::Minidump ? L"Minidump" : k == DumpKind::System ? L"Sys crash dump" : L"App crash dump";
}

std::vector<DumpSource> FindCrashDumps(bool minidumps, bool system, bool app, std::vector<std::wstring>* searched) {
    Finder f(minidumps, system, app, searched);
    const wchar_t* kCrash = L"SYSTEM\\CurrentControlSet\\Control\\CrashControl";
    std::wstring sysRoot = Expand(L"%SystemRoot%");

    // Blue-screen dumps and live kernel reports.
    f.Folder(RegString(HKEY_LOCAL_MACHINE, kCrash, L"MinidumpDir", L"%SystemRoot%\\Minidump"),
             DumpKind::Minidump, false);
    f.File(RegString(HKEY_LOCAL_MACHINE, kCrash, L"DumpFile", L"%SystemRoot%\\MEMORY.DMP"), DumpKind::System);
    f.Folder(sysRoot + L"\\LiveKernelReports", DumpKind::System, true);

    // Windows Error Reporting: machine-wide report folders (kernel and app).
    std::wstring wer = Expand(L"%ProgramData%\\Microsoft\\Windows\\WER");
    for (const wchar_t* sub : { L"\\ReportArchive", L"\\ReportQueue" })
        f.Folder(wer + sub, DumpKind::App, true, true);

    // Per profile (users, plus the system and service accounts): app crash
    // dumps and the user's own WER report folders.
    const wchar_t* kProfiles = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    HKEY hp = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kProfiles, 0, KEY_READ, &hp) == ERROR_SUCCESS) {
        wchar_t sid[256];
        for (DWORD i = 0;; ++i) {
            DWORD n = _countof(sid);
            if (RegEnumKeyExW(hp, i, sid, &n, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            std::wstring key = std::wstring(kProfiles) + L"\\" + sid;
            std::wstring prof = RegString(HKEY_LOCAL_MACHINE, key.c_str(), L"ProfileImagePath", L"");
            if (prof.empty()) continue;
            f.Folder(prof + L"\\AppData\\Local\\CrashDumps", DumpKind::App, true);
            for (const wchar_t* sub : { L"\\ReportArchive", L"\\ReportQueue" })
                f.Folder(prof + L"\\AppData\\Local\\Microsoft\\Windows\\WER" + sub, DumpKind::App, true, true);
        }
        RegCloseKey(hp);
    }

    // LocalDumps: a machine-wide DumpFolder and per-program ones.
    const wchar_t* kLocal = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps";
    f.Folder(RegString(HKEY_LOCAL_MACHINE, kLocal, L"DumpFolder", L""), DumpKind::App, true);
    HKEY hl = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kLocal, 0, KEY_READ, &hl) == ERROR_SUCCESS) {
        wchar_t prog[256];
        for (DWORD i = 0;; ++i) {
            DWORD n = _countof(prog);
            if (RegEnumKeyExW(hl, i, prog, &n, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            std::wstring key = std::wstring(kLocal) + L"\\" + prog;
            f.Folder(RegString(HKEY_LOCAL_MACHINE, key.c_str(), L"DumpFolder", L""), DumpKind::App, true);
        }
        RegCloseKey(hl);
    }
    return f.Take();
}
