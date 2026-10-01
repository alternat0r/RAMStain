// Raw NTFS reading of a locked file - see ntfs_raw.h.
#include "ntfs_raw.h"
#include <winioctl.h>
#include <algorithm>

static UINT16 Rd16(const BYTE* p) { return (UINT16)(p[0] | (p[1] << 8)); }
static UINT32 Rd32(const BYTE* p) { return (UINT32)Rd16(p) | ((UINT32)Rd16(p + 2) << 16); }
static UINT64 Rd64(const BYTE* p) { return (UINT64)Rd32(p) | ((UINT64)Rd32(p + 4) << 32); }
static const UINT64 kMftRefMask = 0x0000FFFFFFFFFFFFull;   // record number (low 48 bits)

// MFT record number of path, read from its parent directory's listing.
static bool FindFileRecordNumber(const std::wstring& path, UINT64& frn) {
    size_t sl = path.find_last_of(L"\\/");
    if (sl == std::wstring::npos) return false;
    std::wstring dir = path.substr(0, sl + 1), name = path.substr(sl + 1);
    HANDLE hd = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hd == INVALID_HANDLE_VALUE) return false;
    std::vector<ULONGLONG> buf(64 * 1024 / sizeof(ULONGLONG));   // 8-byte aligned
    FILE_INFO_BY_HANDLE_CLASS cls = FileIdBothDirectoryRestartInfo;
    bool found = false;
    while (!found && GetFileInformationByHandleEx(hd, cls, buf.data(),
                                                  (DWORD)(buf.size() * sizeof(ULONGLONG)))) {
        cls = FileIdBothDirectoryInfo;
        auto* e = (FILE_ID_BOTH_DIR_INFO*)buf.data();
        for (;;) {
            std::wstring n(e->FileName, e->FileNameLength / sizeof(wchar_t));
            if (_wcsicmp(n.c_str(), name.c_str()) == 0) {
                frn = (UINT64)e->FileId.QuadPart;
                found = true;
                break;
            }
            if (!e->NextEntryOffset) break;
            e = (FILE_ID_BOTH_DIR_INFO*)((BYTE*)e + e->NextEntryOffset);
        }
    }
    CloseHandle(hd);
    return found;
}

// One MFT record (FILE record segment) by number, with the update-sequence
// fixups applied if the driver has not already applied them.
static bool ReadMftRecord(HANDLE vol, UINT64 frn, DWORD recSize, std::vector<BYTE>& rec) {
    NTFS_FILE_RECORD_INPUT_BUFFER in;
    in.FileReferenceNumber.QuadPart = (LONGLONG)(frn & kMftRefMask);
    std::vector<BYTE> out(sizeof(NTFS_FILE_RECORD_OUTPUT_BUFFER) + recSize);
    DWORD br = 0;
    if (!DeviceIoControl(vol, FSCTL_GET_NTFS_FILE_RECORD, &in, sizeof(in),
                         out.data(), (DWORD)out.size(), &br, nullptr))
        return false;
    auto* o = (NTFS_FILE_RECORD_OUTPUT_BUFFER*)out.data();
    // The FSCTL returns the nearest in-use record at or below the one asked for.
    if (((UINT64)o->FileReferenceNumber.QuadPart & kMftRefMask) != (frn & kMftRefMask))
        return false;
    if (o->FileRecordLength < 64 || o->FileRecordLength > recSize) return false;
    rec.assign(o->FileRecordBuffer, o->FileRecordBuffer + o->FileRecordLength);
    if (memcmp(rec.data(), "FILE", 4) != 0) return false;
    UINT16 usaOff = Rd16(&rec[4]), usaCount = Rd16(&rec[6]);
    if (usaCount >= 2 && (size_t)usaOff + usaCount * 2u <= rec.size()) {
        size_t stride = rec.size() / (usaCount - 1);
        UINT16 usn = Rd16(&rec[usaOff]);
        bool present = true;
        for (UINT16 i = 1; i < usaCount && present; ++i)
            present = i * stride <= rec.size() && Rd16(&rec[i * stride - 2]) == usn;
        if (present)
            for (UINT16 i = 1; i < usaCount; ++i)
                memcpy(&rec[i * stride - 2], &rec[usaOff + 2 * i], 2);
    }
    return true;
}

// Decode an NTFS mapping-pairs array (the run list) starting at file cluster vcn.
static bool DecodeRuns(const BYTE* p, const BYTE* end, UINT64 vcn, std::vector<RawExtent>& out) {
    INT64 lcn = 0;
    while (p < end && *p) {
        int lenSz = *p & 0x0F, offSz = *p >> 4;
        ++p;
        if (lenSz == 0 || lenSz > 8 || offSz > 8 || p + lenSz + offSz > end) return false;
        UINT64 len = 0;
        for (int i = 0; i < lenSz; ++i) len |= (UINT64)p[i] << (8 * i);
        p += lenSz;
        if (offSz == 0) {
            out.push_back({ vcn, 0, len, true });            // sparse run
        } else {
            UINT64 d = 0;
            for (int i = 0; i < offSz; ++i) d |= (UINT64)p[i] << (8 * i);
            if (offSz < 8 && (p[offSz - 1] & 0x80)) d |= ~0ull << (8 * offSz);   // sign-extend
            lcn += (INT64)d;
            if (lcn < 0) return false;
            out.push_back({ vcn, (UINT64)lcn, len, false });
        }
        p += offSz;
        vcn += len;
    }
    return true;
}

// Read whole clusters of a run list from the volume (for a non-resident
// attribute list; small).
static bool ReadRunsRaw(HANDLE vol, UINT64 cluster, const std::vector<RawExtent>& runs,
                        UINT64 bytes, std::vector<BYTE>& out) {
    out.clear();
    for (const RawExtent& e : runs) {
        size_t at = out.size();
        out.resize(at + (size_t)(e.clusters * cluster));
        if (e.sparse) continue;
        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)(e.lcn * cluster);
        DWORD rd = 0;
        if (!SetFilePointerEx(vol, li, nullptr, FILE_BEGIN) ||
            !ReadFile(vol, &out[at], (DWORD)(e.clusters * cluster), &rd, nullptr) ||
            rd != e.clusters * cluster)
            return false;
    }
    if (out.size() < bytes) return false;
    out.resize((size_t)bytes);
    return true;
}

// Walk one record's attributes: add the unnamed $DATA runs to map (sizes from
// the segment that starts at VCN 0) and, when attrList is given, return the
// $ATTRIBUTE_LIST contents.
static bool ParseDataAttribute(const std::vector<BYTE>& rec, RawFileMap& map, bool& haveSizes,
                               std::vector<BYTE>* attrList, std::wstring& err) {
    size_t a = Rd16(&rec[0x14]);                          // first attribute
    while (a + 16 <= rec.size()) {
        UINT32 type = Rd32(&rec[a]);
        if (type == 0xFFFFFFFF) break;
        UINT32 len = Rd32(&rec[a + 4]);
        if (len < 16 || a + len > rec.size()) { err = L"malformed MFT record"; return false; }
        const BYTE* at = &rec[a];
        bool nonResident = at[8] != 0;
        BYTE nameLen = at[9];
        UINT16 flags = Rd16(at + 0x0C);
        if (type == 0x80 && nameLen == 0) {
            if (!nonResident || len < 0x40) { err = L"unexpected resident $DATA"; return false; }
            if (flags & 0x4001) { err = L"file is compressed or encrypted"; return false; }
            UINT64 startVcn = Rd64(at + 0x10);
            if (startVcn == 0) {
                map.size = Rd64(at + 0x30);
                map.validSize = Rd64(at + 0x38);
                haveSizes = true;
            }
            if (!DecodeRuns(at + Rd16(at + 0x20), at + len, startVcn, map.extents)) {
                err = L"malformed run list";
                return false;
            }
        } else if (type == 0x20 && attrList) {            // $ATTRIBUTE_LIST
            if (!nonResident) {
                UINT32 vlen = Rd32(at + 0x10);
                UINT16 voff = Rd16(at + 0x14);
                if ((size_t)voff + vlen > len) { err = L"malformed attribute list"; return false; }
                attrList->assign(at + voff, at + voff + vlen);
            } else {
                std::vector<RawExtent> runs;
                if (len < 0x40 || !DecodeRuns(at + Rd16(at + 0x20), at + len, 0, runs) ||
                    !ReadRunsRaw(map.volume, map.cluster, runs, Rd64(at + 0x30), *attrList)) {
                    err = L"could not read the attribute list";
                    return false;
                }
            }
        }
        a += len;
    }
    return true;
}

// Build the cluster map of a locked file on an NTFS volume (see above).
bool MapLockedFile(const std::wstring& path, RawFileMap& map, std::wstring& err) {
    wchar_t mount[MAX_PATH] = L"", vol[MAX_PATH] = L"", fs[64] = L"";
    if (!GetVolumePathNameW(path.c_str(), mount, MAX_PATH) ||
        !GetVolumeInformationW(mount, nullptr, 0, nullptr, nullptr, nullptr, fs, 64) ||
        !GetVolumeNameForVolumeMountPointW(mount, vol, MAX_PATH)) {
        err = L"could not identify the volume of " + path + L" (error " + std::to_wstring(GetLastError()) + L")";
        return false;
    }
    if (_wcsicmp(fs, L"NTFS") != 0) {
        err = path + L" is on a " + fs + L" volume; reading a locked file is supported on NTFS only";
        return false;
    }
    std::wstring volPath = vol;
    if (!volPath.empty() && volPath.back() == L'\\') volPath.pop_back();   // \\?\Volume{...}
    map.volume = CreateFileW(volPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING, 0, nullptr);
    if (map.volume == INVALID_HANDLE_VALUE) {
        err = L"could not open the volume for raw reading (error " + std::to_wstring(GetLastError()) + L")";
        return false;
    }
    NTFS_VOLUME_DATA_BUFFER vd = {};
    DWORD br = 0;
    if (!DeviceIoControl(map.volume, FSCTL_GET_NTFS_VOLUME_DATA, nullptr, 0, &vd, sizeof(vd), &br, nullptr)) {
        err = L"could not read NTFS volume data (error " + std::to_wstring(GetLastError()) + L")";
        return false;
    }
    map.cluster = vd.BytesPerCluster;
    DWORD recSize = vd.BytesPerFileRecordSegment;

    UINT64 frn = 0;
    std::vector<BYTE> rec, attrList;
    bool haveSizes = false;
    if (!FindFileRecordNumber(path, frn) || !ReadMftRecord(map.volume, frn, recSize, rec)) {
        err = L"could not locate the MFT record of " + path;
        return false;
    }
    if (!ParseDataAttribute(rec, map, haveSizes, &attrList, err)) return false;

    // A heavily fragmented file continues its $DATA runs in other records,
    // listed in $ATTRIBUTE_LIST: type u32 @0, length u16 @4, name length @6,
    // record reference u64 @0x10.
    std::vector<UINT64> seen{ frn & kMftRefMask };
    for (size_t o = 0; o + 0x1A <= attrList.size();) {
        UINT16 elen = Rd16(&attrList[o + 4]);
        if (elen < 0x1A || o + elen > attrList.size()) break;
        UINT64 ref = Rd64(&attrList[o + 0x10]) & kMftRefMask;
        if (Rd32(&attrList[o]) == 0x80 && attrList[o + 6] == 0 &&
            std::find(seen.begin(), seen.end(), ref) == seen.end()) {
            seen.push_back(ref);
            std::vector<BYTE> ext;
            if (!ReadMftRecord(map.volume, ref, recSize, ext) ||
                !ParseDataAttribute(ext, map, haveSizes, nullptr, err)) {
                if (err.empty()) err = L"could not read an extension MFT record";
                return false;
            }
        }
        o += elen;
    }

    // The runs must cover the file from cluster 0 without gaps.
    std::sort(map.extents.begin(), map.extents.end(),
              [](const RawExtent& x, const RawExtent& y) { return x.vcn < y.vcn; });
    UINT64 next = 0;
    for (const RawExtent& e : map.extents) {
        if (e.vcn != next) { err = L"incomplete cluster map"; return false; }
        next += e.clusters;
    }
    if (!haveSizes || next * map.cluster < map.size) { err = L"incomplete cluster map"; return false; }
    if (map.validSize > map.size) map.validSize = map.size;
    return true;
}
