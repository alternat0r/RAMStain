#pragma once
#include <windows.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
//  Raw NTFS reading of a locked file
//
//  The kernel opens pagefile.sys and hiberfil.sys with no sharing at all, so
//  CreateFile fails with ERROR_SHARING_VIOLATION even for an Administrator,
//  even for attribute-only access. Instead: list the parent directory (which
//  gives the file's MFT record number without opening the file), fetch that
//  record from the volume with FSCTL_GET_NTFS_FILE_RECORD, decode the cluster
//  runs of its unnamed $DATA attribute, and read those clusters directly from
//  the volume. NTFS only. The file is live, so the copy reflects its contents
//  at the moment each block is read (as with any live acquisition).
// ---------------------------------------------------------------------------

// One run of clusters: file clusters [vcn, vcn + clusters) are at volume
// cluster lcn (or not allocated at all when sparse - they read as zeros).
struct RawExtent { UINT64 vcn, lcn, clusters; bool sparse; };

struct RawFileMap {
    HANDLE volume = INVALID_HANDLE_VALUE;   // opened for raw reads
    UINT64 cluster = 0;                     // bytes per cluster
    UINT64 size = 0;                        // file size
    UINT64 validSize = 0;                   // initialized size; bytes past it read as zero
    std::vector<RawExtent> extents;         // sorted by vcn, covering the file
    RawFileMap() = default;
    RawFileMap(const RawFileMap&) = delete;
    RawFileMap& operator=(const RawFileMap&) = delete;
    ~RawFileMap() { if (volume != INVALID_HANDLE_VALUE) CloseHandle(volume); }
};

// Build the cluster map of a locked file on an NTFS volume. False with err set
// (a short reason) when the file cannot be mapped.
bool MapLockedFile(const std::wstring& path, RawFileMap& map, std::wstring& err);

// Sequential reader over a RawFileMap. cap (the buffer size) must be a
// multiple of the cluster size and buf sector-aligned.
class RawFileReader {
public:
    explicit RawFileReader(const RawFileMap& m) : m_map(m) {}
    // Next bytes of the file (got = 0 at the end). False on a read error.
    bool Read(BYTE* buf, DWORD cap, DWORD& got) {
        got = 0;
        if (m_off >= m_map.size) return true;
        const UINT64 cl = m_map.cluster;
        while (m_i < m_map.extents.size() &&
               (m_map.extents[m_i].vcn + m_map.extents[m_i].clusters) * cl <= m_off)
            ++m_i;
        if (m_i >= m_map.extents.size()) return false;
        const RawExtent& e = m_map.extents[m_i];
        UINT64 inExt = m_off - e.vcn * cl;                               // cluster-aligned
        UINT64 len = min((UINT64)cap, e.clusters * cl - inExt);          // whole clusters
        if (e.sparse) {
            memset(buf, 0, (size_t)len);
        } else {
            LARGE_INTEGER li;
            li.QuadPart = (LONGLONG)(e.lcn * cl + inExt);
            DWORD rd = 0;
            if (!SetFilePointerEx(m_map.volume, li, nullptr, FILE_BEGIN) ||
                !ReadFile(m_map.volume, buf, (DWORD)len, &rd, nullptr) || rd != len)
                return false;
        }
        UINT64 n = min(len, m_map.size - m_off);
        if (m_off + n > m_map.validSize) {                               // past valid data
            UINT64 z = m_map.validSize > m_off ? m_map.validSize - m_off : 0;
            memset(buf + z, 0, (size_t)(n - z));
        }
        m_off += n;
        got = (DWORD)n;
        return true;
    }
private:
    const RawFileMap& m_map;
    size_t m_i = 0;
    UINT64 m_off = 0;
};
