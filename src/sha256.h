// SHA-256 via Windows CNG (bcrypt.dll, part of Windows since Vista) - no
// third-party code, and CNG uses the CPU's SHA extensions where available.
// Interface: Update(), Hex() (finalizes), Reset().
#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <string>
#pragma comment(lib, "bcrypt.lib")

class SHA256 {
public:
    SHA256() { Reset(); }
    ~SHA256() { Close(); if (m_alg) BCryptCloseAlgorithmProvider(m_alg, 0); }
    SHA256(const SHA256&) = delete;
    SHA256& operator=(const SHA256&) = delete;

    void Reset() {
        Close();
        if (!m_alg && BCryptOpenAlgorithmProvider(&m_alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            m_alg = nullptr;
        // Win10+: CNG allocates the hash object itself when no buffer is given.
        if (m_alg && BCryptCreateHash(m_alg, &m_hash, nullptr, 0, nullptr, 0, 0) != 0)
            m_hash = nullptr;
    }

    void Update(const unsigned char* data, size_t n) {
        while (m_hash && n > 0) {
            ULONG chunk = (ULONG)(n > 0x40000000 ? 0x40000000 : n);
            if (BCryptHashData(m_hash, (PUCHAR)data, chunk, 0) != 0) { Close(); m_failed = true; return; }
            data += chunk;
            n -= chunk;
        }
    }

    // Lower-case hex digest; empty string if CNG failed (shown as "not computed").
    std::string Hex() {
        unsigned char d[32];
        bool ok = m_hash && !m_failed && BCryptFinishHash(m_hash, d, sizeof(d), 0) == 0;
        Close();
        if (!ok) return std::string();
        static const char* kHex = "0123456789abcdef";
        std::string s;
        s.reserve(64);
        for (unsigned char b : d) { s.push_back(kHex[b >> 4]); s.push_back(kHex[b & 0x0f]); }
        return s;
    }

private:
    void Close() {
        if (m_hash) { BCryptDestroyHash(m_hash); m_hash = nullptr; }
        m_failed = false;
    }
    BCRYPT_ALG_HANDLE  m_alg = nullptr;
    BCRYPT_HASH_HANDLE m_hash = nullptr;
    bool m_failed = false;
};
