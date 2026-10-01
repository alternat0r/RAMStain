// --verify: re-hash a capture's files and compare them with the SHA-256
// recorded in its .meta sidecars.
#pragma once
#include <functional>
#include <string>

// Verify the capture in `target`: a run folder (RAMstain_<timestamp>), a
// folder holding several run folders, or a single .meta file. Each file is
// looked up by name next to its .meta, so a capture copied elsewhere still
// verifies. Progress and results go to `out`, one line per call.
// Returns 0 when everything with a recorded hash matched, 1 when any file is
// missing or differs, 2 when there was nothing to verify.
int VerifyCapture(const std::wstring& target, const std::function<void(const std::wstring&)>& out);
