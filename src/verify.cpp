// --verify - see verify.h.
#include "verify.h"
#include "hash_pipeline.h"
#include "util.h"
#include <cwctype>
#include <vector>

namespace {

// One thing to check: these files, joined in order, must hash to `sha`. A
// split image adds `partSha` (one per file) so a single pass checks both the
// whole image and each part.
struct Item {
    std::wstring label;                 // shown in the output
    std::vector<std::wstring> files;    // full paths, in order
    std::string sha;                    // expected whole SHA-256 (lower-case hex), "" = none recorded
    std::vector<std::string> partSha;   // split image only: expected per-part hashes
    UINT64 partSize = 0;                // split image only: size of every part but the last
    std::wstring note;                  // why it cannot be checked (sha empty)
};

std::wstring Trim(const std::wstring& s) {
    size_t b = s.find_first_not_of(L" \t\r");
    size_t e = s.find_last_not_of(L" \t\r");
    return b == std::wstring::npos ? std::wstring() : s.substr(b, e - b + 1);
}

std::wstring FileName(const std::wstring& p) {
    size_t sl = p.find_last_of(L"\\/");
    return sl == std::wstring::npos ? p : p.substr(sl + 1);
}

bool IsSha(const std::wstring& v) {
    if (v.size() != 64) return false;
    for (wchar_t c : v) if (!iswxdigit(c)) return false;
    return true;
}

std::string Lower(const std::wstring& v) {     // v is hex (checked by IsSha)
    std::string s = WideToUtf8(v);
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

std::vector<std::wstring> ReadLines(const std::wstring& path) {
    std::vector<std::wstring> lines;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return lines;
    LARGE_INTEGER sz = {0};
    GetFileSizeEx(h, &sz);
    std::string bytes((size_t)min(sz.QuadPart, 1 << 20), '\0');   // sidecars are small
    DWORD rd = 0;
    ReadFile(h, &bytes[0], (DWORD)bytes.size(), &rd, nullptr);
    CloseHandle(h);
    bytes.resize(rd);
    std::wstring text = Utf8ToWide(bytes);
    size_t i = 0;
    while (i <= text.size()) {
        size_t e = text.find(L'\n', i);
        if (e == std::wstring::npos) e = text.size();
        std::wstring line = text.substr(i, e - i);
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        lines.push_back(line);
        i = e + 1;
    }
    return lines;
}

// "Key:   value" -> value (trimmed), when the line starts with key (no indent).
bool Field(const std::wstring& line, const wchar_t* key, std::wstring& value) {
    size_t n = wcslen(key);
    if (line.compare(0, n, key) != 0) return false;
    value = Trim(line.substr(n));
    return true;
}

// Items from one .meta sidecar (capture or system file).
std::vector<Item> ParseMeta(const std::wstring& metaPath) {
    std::vector<Item> items;
    std::wstring dir = metaPath.substr(0, metaPath.find_last_of(L"\\/"));
    std::vector<std::wstring> lines = ReadLines(metaPath);
    if (lines.empty()) return items;
    bool capture = lines[0].find(L"capture metadata") != std::wstring::npos;
    bool sysfile = lines[0].find(L"system file metadata") != std::wstring::npos;
    bool dumps   = lines[0].find(L"crash dump collection") != std::wstring::npos;

    // Crash dump manifest: "File 001:    crashdumps\C\...\x.dmp" (relative to
    // the manifest's folder), then indented details incl. "  SHA-256:   <hash>".
    if (dumps) {
        for (size_t i = 0; i < lines.size(); ++i) {
            const std::wstring& l = lines[i];
            if (l.size() < 6 || l.compare(0, 5, L"File ") != 0 || !iswdigit(l[5])) continue;
            Item it;
            std::wstring rel = Trim(l.substr(l.find(L':') + 1));
            it.label = rel;
            it.files = { dir + L"\\" + rel };
            std::wstring sha, v;
            for (size_t j = i + 1; j < lines.size() && lines[j].compare(0, 2, L"  ") == 0; ++j)
                if (Field(Trim(lines[j]), L"SHA-256:", v)) sha = v;
            if (IsSha(sha)) it.sha = Lower(sha);
            else it.note = L"not collected (see the manifest)";
            items.push_back(it);
        }
        return items;
    }
    if (!capture && !sysfile) return items;

    std::wstring file, sha, v;
    bool splitIncomplete = false;
    std::vector<std::wstring> parts;
    std::vector<std::string> partSha;
    UINT64 partSize = 0;
    for (size_t i = 0; i < lines.size(); ++i) {
        const std::wstring& l = lines[i];
        if (capture && Field(l, L"Image:", v)) file = v;
        else if (sysfile && Field(l, L"Collected:", v)) file = v;
        else if (Field(l, L"SHA-256:", v)) { if (sha.empty()) sha = v; }
        else if (l.compare(0, 5, L"Part ") == 0) {
            // "Part 001:    host1.001  4293918720 bytes" then "  SHA-256:   <hash>"
            size_t colon = l.find(L':');
            std::wstring rest = Trim(l.substr(colon + 1));
            size_t sp = rest.find(L"  ");
            std::wstring name = Trim(rest.substr(0, sp));
            UINT64 bytes = wcstoull(Trim(rest.substr(sp)).c_str(), nullptr, 10);
            if (parts.empty()) partSize = bytes;
            parts.push_back(dir + L"\\" + name);
            std::wstring ph;
            if (i + 1 < lines.size()) {
                std::wstring next = Trim(lines[i + 1]);
                if (Field(next, L"SHA-256:", ph)) ++i;
            }
            partSha.push_back(IsSha(ph) ? Lower(ph) : std::string());
        } else if (l.find(L"Split incomplete") != std::wstring::npos) splitIncomplete = true;
    }

    Item it;
    if (!parts.empty()) {
        it.label = FileName(parts.front()) + L" ... " + FileName(parts.back()) +
                   L" (" + std::to_wstring(parts.size()) + L" parts, whole image)";
        it.files = parts;
        it.partSha = partSha;
        it.partSize = partSize;
    } else {
        if (file.empty() || file == L"(not collected)") return items;   // nothing was written
        it.label = FileName(file);
        it.files = { dir + L"\\" + FileName(file) };
    }
    if (IsSha(sha) && !splitIncomplete) it.sha = Lower(sha);
    else it.note = splitIncomplete ? L"split incomplete (see its .meta)" : L"no hash recorded (" + sha + L")";
    items.push_back(it);
    return items;
}

void FindMetas(const std::wstring& dir, std::vector<std::wstring>& metas, bool descend) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    std::vector<std::wstring> subdirs;
    do {
        std::wstring n = fd.cFileName;
        if (n == L"." || n == L"..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (descend && n.compare(0, 9, L"RAMstain_") == 0) subdirs.push_back(dir + L"\\" + n);
        } else if (n.size() > 5 && _wcsicmp(n.c_str() + n.size() - 5, L".meta") == 0) {
            metas.push_back(dir + L"\\" + n);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    for (const auto& d : subdirs) FindMetas(d, metas, false);
}

std::wstring Gb(UINT64 b) {                    // "16 MB" below 1 GB, else "13.50 GB"
    wchar_t buf[32];
    if (b < (1ull << 30))
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%llu MB", (b + (1ull << 20) - 1) >> 20);
    else
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%.2f GB", b / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

}  // namespace

int VerifyCapture(const std::wstring& targetIn, const std::function<void(const std::wstring&)>& out) {
    std::wstring target = targetIn;
    while (target.size() > 3 && (target.back() == L'\\' || target.back() == L'/')) target.pop_back();
    std::vector<std::wstring> metas;
    DWORD a = GetFileAttributesW(target.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) {
        out(L"Not found: " + target);
        return 2;
    }
    if (a & FILE_ATTRIBUTE_DIRECTORY) FindMetas(target, metas, true);
    else metas.push_back(target);

    std::vector<Item> items;
    for (const auto& m : metas) {
        std::vector<Item> got = ParseMeta(m);
        items.insert(items.end(), got.begin(), got.end());
    }
    if (items.empty()) {
        out(L"Nothing to verify: no RAMstain .meta sidecars with collected files in " + target);
        return 2;
    }
    out(L"Verifying " + std::to_wstring(items.size()) + L" item(s) in " + target);

    int ok = 0, bad = 0, skipped = 0;
    const DWORD kBlock = 8 * 1024 * 1024;
    for (const Item& it : items) {
        if (it.sha.empty()) {
            out(L"SKIPPED   " + it.label + L" - " + it.note);
            ++skipped;
            continue;
        }
        // Hash the files in order (read and hash overlap; parts hashed in the same pass).
        HashPipeline hash(kBlock, it.partSize);
        UINT64 total = 0;
        std::wstring missing, readErr;
        for (const auto& f : it.files) {
            HANDLE h = CreateFileW(f.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                   FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (h == INVALID_HANDLE_VALUE) { missing = f; break; }
            for (;;) {
                BYTE* buf = hash.Acquire();
                DWORD rd = 0;
                if (!ReadFile(h, buf, kBlock, &rd, nullptr)) {
                    readErr = f + L" (read error " + std::to_wstring(GetLastError()) + L")";
                    break;
                }
                if (rd == 0) break;
                hash.Submit(rd);
                total += rd;
            }
            CloseHandle(h);
            if (!readErr.empty()) break;
        }
        if (!missing.empty()) { out(L"MISSING   " + it.label + L" - " + FileName(missing) + L" not found"); ++bad; continue; }
        if (!readErr.empty()) { out(L"FAILED    " + it.label + L" - " + readErr); ++bad; continue; }
        std::vector<std::string> parts;
        std::string actual = hash.Finish(it.partSha.empty() ? nullptr : &parts);
        bool match = actual == it.sha;
        std::wstring partNote;
        for (size_t i = 0; i < it.partSha.size(); ++i) {
            if (it.partSha[i].empty()) continue;
            if (i >= parts.size() || parts[i] != it.partSha[i]) {
                match = false;
                partNote += L" " + FileName(it.files[i]);
            }
        }
        if (match) {
            out(L"OK        " + it.label + L"  (" + Gb(total) + L", SHA-256 " + Utf8ToWide(actual) + L")");
            ++ok;
        } else {
            out(L"MISMATCH  " + it.label + L"\n          expected " + Utf8ToWide(it.sha) +
                L"\n          actual   " + Utf8ToWide(actual) +
                (partNote.empty() ? L"" : L"\n          parts differing:" + partNote));
            ++bad;
        }
    }
    out(L"Result: " + std::to_wstring(ok) + L" OK, " + std::to_wstring(bad) + L" failed, " +
        std::to_wstring(skipped) + L" skipped" + (bad ? L" - VERIFICATION FAILED" : L""));
    return bad ? 1 : (ok ? 0 : 2);
}
