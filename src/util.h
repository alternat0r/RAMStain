// Small string helpers shared by the RAMstain sources.
#pragma once
#include <windows.h>
#include <string>

inline std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w;
    if (n > 0) { w.resize(n); MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n); }
    return w;
}

inline std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s;
    if (n > 0) { s.resize(n); WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr); }
    return s;
}
