// Finding the memory dumps Windows writes: minidumps and the system crash dump
// after a blue screen, live kernel reports, and Windows Error Reporting dumps
// of crashed programs.
#pragma once
#include <windows.h>
#include <string>
#include <vector>

enum class DumpKind { Minidump, System, App };

struct DumpSource {
    DumpKind     kind;
    std::wstring path;          // full path of the dump file
    UINT64       bytes = 0;
    FILETIME     created = {};  // the dump file's own timestamps (UTC)
    FILETIME     modified = {};
};

// "Minidump" / "System crash dump" / "App crash dump".
const wchar_t* DumpKindName(DumpKind k);

// The dumps of the requested kinds on this system (deduplicated, sorted by
// path), from:
//   Minidump  CrashControl\MinidumpDir (default %SystemRoot%\Minidump)
//   System    CrashControl\DumpFile (default %SystemRoot%\MEMORY.DMP),
//             %SystemRoot%\LiveKernelReports, and Kernel_* WER reports
//   App       every profile's AppData\Local\CrashDumps, the WER report
//             archive/queue folders (machine and per user), and any
//             LocalDumps DumpFolder set in the registry
// File types: *.dmp, *.mdmp, *.hdmp. Junctions and other reparse points are
// not followed. `searched` (optional) receives the folders/files looked at.
std::vector<DumpSource> FindCrashDumps(bool minidumps, bool system, bool app,
                                       std::vector<std::wstring>* searched = nullptr);
