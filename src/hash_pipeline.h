// SHA-256 hashing helpers: one stream (ImageHash), fixed-size slices of a
// stream (PartHasher, for split images), and HashPipeline, which hashes on
// background threads while the caller reads the next block.
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "sha256.h"

// SHA-256 of a byte stream, fed in one pass.
struct ImageHash {
    SHA256 sha256;
    void Update(const BYTE* p, size_t n) { sha256.Update(p, n); }
};

// Hashes of consecutive fixed-size slices of a byte stream, computed alongside
// the whole-image hashes so a split image gets per-part hashes without a
// second pass over the data. partSize 0 = disabled.
struct PartHasher {
    UINT64 partSize = 0, inPart = 0;
    ImageHash cur;
    std::vector<std::string> sha256s;
    explicit PartHasher(UINT64 ps) : partSize(ps) {}
    void Update(const BYTE* p, size_t n) {
        if (!partSize) return;
        while (n > 0) {
            size_t take = (size_t)min((UINT64)n, partSize - inPart);
            cur.Update(p, take);
            inPart += take; p += take; n -= take;
            if (inPart == partSize) Close();
        }
    }
    // Call once at the end; moves the per-part hashes into out.
    void Finish(std::vector<std::string>& out) {
        if (partSize && inPart > 0) Close();
        out = std::move(sha256s);
    }
private:
    void Close() {
        sha256s.push_back(cur.sha256.Hex());
        cur.sha256.Reset();
        inPart = 0;
    }
};

// Hashes a byte stream on background threads, so the caller can read (and
// write) the next block while earlier blocks are still being hashed: the time
// is max(I/O, hashing) instead of their sum. The whole-image hash and the
// per-part hashes (partSize != 0) each get their own thread, so splitting
// does not double the hashing time.
//
// Usage: fill the buffer from Acquire(), hand it over with Submit(n), repeat;
// then Finish() for the digests. kSlots buffers rotate, so reading runs up to
// kSlots - 1 blocks ahead of hashing. Destroying the pipeline without calling
// Finish() abandons the hash (Stop pressed / error). If a thread cannot be
// started, that hash is computed inline in Submit() instead.
class HashPipeline {
public:
    HashPipeline(size_t blockBytes, UINT64 partSize) : m_parts(partSize) {
        // Page-aligned (VirtualAlloc), as raw volume reads require.
        for (Slot& s : m_slot)
            s.buf = (BYTE*)VirtualAlloc(nullptr, blockBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        m_thread[0] = CreateThread(nullptr, 0, WholeThread, this, 0, nullptr);
        if (partSize)
            m_thread[1] = CreateThread(nullptr, 0, PartThread, this, 0, nullptr);
        m_consumers = (m_thread[0] ? 1 : 0) + (m_thread[1] ? 1 : 0);
    }
    ~HashPipeline() {
        Join(true);
        for (Slot& s : m_slot) if (s.buf) VirtualFree(s.buf, 0, MEM_RELEASE);
    }
    HashPipeline(const HashPipeline&) = delete;
    HashPipeline& operator=(const HashPipeline&) = delete;

    // Next buffer to fill (blockBytes long); waits while all are being hashed.
    BYTE* Acquire() {
        Slot& s = m_slot[m_submitted % kSlots];
        AcquireSRWLockExclusive(&m_lock);
        while (s.pending > 0)
            SleepConditionVariableSRW(&m_cv, &m_lock, INFINITE, 0);
        ReleaseSRWLockExclusive(&m_lock);
        return s.buf;
    }

    // Hand the first n bytes of the buffer from Acquire() to the hashers.
    void Submit(size_t n) {
        Slot& s = m_slot[m_submitted % kSlots];
        s.n = n;
        if (!m_thread[0]) m_whole.Update(s.buf, n);
        if (m_parts.partSize && !m_thread[1]) m_parts.Update(s.buf, n);
        AcquireSRWLockExclusive(&m_lock);
        s.pending = m_consumers;
        ++m_submitted;
        ReleaseSRWLockExclusive(&m_lock);
        WakeAllConditionVariable(&m_cv);
    }

    // Wait until everything submitted is hashed. Returns the whole-stream
    // SHA-256; per-part hashes go to partHashes when given.
    std::string Finish(std::vector<std::string>* partHashes = nullptr) {
        Join(false);
        if (partHashes) m_parts.Finish(*partHashes);
        return m_whole.sha256.Hex();
    }

private:
    static const int kSlots = 4;
    struct Slot {
        BYTE* buf = nullptr;
        size_t n = 0;
        int pending = 0;          // hasher threads still reading this buffer
    };

    static DWORD WINAPI WholeThread(LPVOID p) { ((HashPipeline*)p)->Consume(false); return 0; }
    static DWORD WINAPI PartThread(LPVOID p)  { ((HashPipeline*)p)->Consume(true);  return 0; }

    void Consume(bool parts) {
        for (UINT64 next = 0;; ++next) {
            AcquireSRWLockExclusive(&m_lock);
            while (next == m_submitted && !m_closing)
                SleepConditionVariableSRW(&m_cv, &m_lock, INFINITE, 0);
            bool have = next < m_submitted && !m_abort;
            ReleaseSRWLockExclusive(&m_lock);
            if (!have) return;
            Slot& s = m_slot[next % kSlots];
            if (parts) m_parts.Update(s.buf, s.n);
            else       m_whole.Update(s.buf, s.n);
            AcquireSRWLockExclusive(&m_lock);
            --s.pending;
            ReleaseSRWLockExclusive(&m_lock);
            WakeAllConditionVariable(&m_cv);
        }
    }

    // abort: stop without hashing the rest. Safe to call more than once.
    void Join(bool abort) {
        AcquireSRWLockExclusive(&m_lock);
        m_closing = true;
        if (abort) m_abort = true;
        ReleaseSRWLockExclusive(&m_lock);
        WakeAllConditionVariable(&m_cv);
        for (HANDLE& t : m_thread) {
            if (!t) continue;
            WaitForSingleObject(t, INFINITE);
            CloseHandle(t);
            t = nullptr;
        }
    }

    Slot       m_slot[kSlots];
    ImageHash  m_whole;
    PartHasher m_parts;
    HANDLE     m_thread[2] = {};
    int        m_consumers = 0;
    UINT64     m_submitted = 0;   // blocks handed to the hashers so far
    bool       m_closing = false; // no more blocks coming
    bool       m_abort = false;   // ... and drop the ones not yet hashed
    SRWLOCK            m_lock = SRWLOCK_INIT;
    CONDITION_VARIABLE m_cv = CONDITION_VARIABLE_INIT;
};
