#pragma once
#include <windows.h>
#include <string>
#include "util.h"

// ---------------------------------------------------------------------------
//  Run log (<image base>.log)
//
//  Each run appends a timestamped record - options, method, every phase,
//  errors, and the results with their hashes - to a text log next to the
//  image. Entries are written and flushed as they happen, so the log survives
//  an interrupted run, and appending keeps the history of earlier runs to the
//  same name. The worker and UI threads both log, so writes are serialized.
// ---------------------------------------------------------------------------
class RunLog {
public:
    // Open for appending (created if missing). On failure the run goes ahead
    // without a log and Path() is empty.
    bool Open(const std::wstring& path) {
        Close();
        m_h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                          OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        m_path = (m_h != INVALID_HANDLE_VALUE) ? path : std::wstring();
        return !m_path.empty();
    }
    void Close() {
        AcquireSRWLockExclusive(&m_lock);
        if (m_h != INVALID_HANDLE_VALUE) CloseHandle(m_h);
        m_h = INVALID_HANDLE_VALUE;
        ReleaseSRWLockExclusive(&m_lock);
    }
    const std::wstring& Path() const { return m_path; }   // kept after Close()

    // One entry, "2026-09-30T13:14:24.123Z  text"; further lines of a
    // multi-line text are indented under it.
    void Line(const std::wstring& text) {
        SYSTEMTIME u;
        GetSystemTime(&u);
        wchar_t ts[32];
        _snwprintf_s(ts, _countof(ts), _TRUNCATE, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ  ",
                     u.wYear, u.wMonth, u.wDay, u.wHour, u.wMinute, u.wSecond, u.wMilliseconds);
        std::wstring line = ts;
        for (wchar_t c : text) {
            if (c == L'\n') line += L"\r\n" + std::wstring(26, L' ');
            else if (c != L'\r') line += c;
        }
        line += L"\r\n";
        std::string u8 = WideToUtf8(line);
        AcquireSRWLockExclusive(&m_lock);
        if (m_h != INVALID_HANDLE_VALUE) {
            DWORD wr = 0;
            WriteFile(m_h, u8.data(), (DWORD)u8.size(), &wr, nullptr);
            FlushFileBuffers(m_h);
        }
        ReleaseSRWLockExclusive(&m_lock);
    }

private:
    HANDLE       m_h = INVALID_HANDLE_VALUE;
    std::wstring m_path;
    SRWLOCK      m_lock = SRWLOCK_INIT;
};
