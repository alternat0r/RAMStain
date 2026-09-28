// ============================================================================
//  MD5 (RFC 1321) - minimal single-header implementation.
//
//  Used here strictly as a capture-integrity hash for the evidence image
//  (same convention as WinPMEM and other memory capture tools), displayed in
//  the UI and written to the .meta sidecar. Not a security primitive.
// ============================================================================
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

class MD5 {
public:
    MD5() { Reset(); }

    void Reset() {
        m_len = 0;
        m_bufLen = 0;
        m_state[0] = 0x67452301u;
        m_state[1] = 0xefcdab89u;
        m_state[2] = 0x98badcfeu;
        m_state[3] = 0x10325476u;
    }

    void Update(const uint8_t* data, size_t n) {
        m_len += n;
        size_t i = 0;
        if (m_bufLen > 0) {
            size_t need = 64 - m_bufLen;
            if (n < need) {
                std::memcpy(m_buf + m_bufLen, data, n);
                m_bufLen += n;
                return;
            }
            std::memcpy(m_buf + m_bufLen, data, need);
            Transform(m_state, m_buf);
            m_bufLen = 0;
            i = need;
        }
        for (; i + 64 <= n; i += 64)
            Transform(m_state, data + i);
        if (i < n) {
            std::memcpy(m_buf, data + i, n - i);
            m_bufLen = n - i;
        }
    }

    std::string Hex() {
        uint8_t digest[16];
        Finalize(digest);
        static const char* kHex = "0123456789abcdef";
        std::string s;
        s.reserve(32);
        for (int i = 0; i < 16; ++i) {
            s.push_back(kHex[digest[i] >> 4]);
            s.push_back(kHex[digest[i] & 0x0f]);
        }
        return s;
    }

private:
    uint32_t m_state[4];
    uint64_t m_len;
    uint8_t  m_buf[64];
    size_t   m_bufLen;

    static uint32_t Rotl(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

    static void Transform(uint32_t s[4], const uint8_t block[64]) {
        static const uint32_t kK[64] = {
            0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
            0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
            0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
            0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
            0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
            0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
            0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
            0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
            0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
            0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
            0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
            0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
            0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
            0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
            0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
            0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
        };
        static const int kS[64] = {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        };

        uint32_t m[16];
        for (int i = 0; i < 16; ++i) {
            const uint8_t* p = block + i * 4;
            m[i] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                   ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        }
        uint32_t a = s[0], b = s[1], c = s[2], d = s[3];
        for (int i = 0; i < 64; ++i) {
            uint32_t f;
            int g;
            if (i < 16)       { f = (b & c) | (~b & d);   g = i; }
            else if (i < 32)  { f = (b & d) | (c & ~d);   g = (5 * i + 1) % 16; }
            else if (i < 48)  { f = b ^ c ^ d;            g = (3 * i + 5) % 16; }
            else              { f = c ^ (b | ~d);         g = (7 * i) % 16; }
            f = f + a + kK[i] + m[g];
            a = d;
            d = c;
            c = b;
            b = b + Rotl(f, kS[i]);
        }
        s[0] += a; s[1] += b; s[2] += c; s[3] += d;
    }

    void Finalize(uint8_t digest[16]) {
        uint64_t bitLen = m_len * 8u;
        std::vector<uint8_t> tail(m_buf, m_buf + m_bufLen);
        tail.push_back(0x80);
        while (tail.size() % 64 != 56) tail.push_back(0);
        for (int i = 0; i < 8; ++i) tail.push_back((uint8_t)(bitLen >> (8 * i)));
        uint32_t s[4] = { m_state[0], m_state[1], m_state[2], m_state[3] };
        for (size_t off = 0; off < tail.size(); off += 64)
            Transform(s, tail.data() + off);
        for (int i = 0; i < 4; ++i) {
            digest[i * 4 + 0] = (uint8_t)(s[i]);
            digest[i * 4 + 1] = (uint8_t)(s[i] >> 8);
            digest[i * 4 + 2] = (uint8_t)(s[i] >> 16);
            digest[i * 4 + 3] = (uint8_t)(s[i] >> 24);
        }
    }
};
