# RAMstain

A compact, offline **physical memory (RAM) capture** tool for Windows, written
in C++ (Win32, zero runtime dependencies) for forensics and incident response.

One goal: get a memory image off a machine **without** the friction of most
commercial/cloud capture tools — **no account, no email, no phone number, no
username, no download registration, no network connection.** RAMstain is a
single EXE that you run and that writes the dump straight to a path you choose.

---

## What it does

RAMstain captures the entire contents of physical RAM using the official,
signed **Velocidex WinPmem** imager, which is **built into `RAMstain.exe`**.
The imager temporarily loads its signed kernel driver, writes the image, and
unloads the driver again. RAMstain drives it from a simple UI and adds the MD5
digest and evidence sidecar described below. Nothing is installed permanently.

An **experimental driverless path** (`OpenProcess` on PID -1 +
`ReadProcessMemory`) is still available by unticking **Use WinPmem driver**,
but it is not a documented Windows API and is expected to fail. See
[Capture methods](#capture-methods).

For each capture it produces two files in the location you specify:

| File | Description |
|------|-------------|
| `<name>.raw`  | The physical memory image, 4 KiB page-aligned. |
| `<name>.meta` | An evidence sidecar: image path, host name, OS + kernel build, capture timestamp, byte size, page count, MD5 digest, tool version, and method. |

An **MD5** digest of the finished image (the same convention WinPMEM uses for
integrity) is written to both the completion dialog and the `.meta` sidecar.

## Key properties

- **Portable single EXE.** Statically linked (no VC++ runtime / MFC /
  redistributable required), ~800 KB with the WinPmem imager embedded. Copy it
  to a USB stick and run it; nothing else is needed. The imager is written to
  a temporary Administrators-only folder only when a capture needs it, and
  deleted when RAMstain closes (see [Capture methods](#capture-methods)).
- **Offline by design.** No network calls, no telemetry, no update downloads.
- **Runs as Administrator** (required to read physical memory).
- **Progress + Stop.** Live progress bar; the **Close** button becomes **Stop**
  during a capture, letting you cancel cleanly (a partial image + sidecar is
  kept and marked as such). No MD5 is computed for a stopped capture, and
  pressing Stop during the MD5 step keeps the complete image but skips the hash.
- **Pre-flight checks.** Warns on an existing destination (overwrite prompt)
  and verifies enough free disk space before starting.
- **Modern UI.** Themed (Common Controls v6), per-monitor DPI aware, owner-drawn
  flat controls.
- **Legal docs built in.** Disclaimer, Privacy Policy, and Terms of Use are
  bundled in the EXE and openable from the footer — no website needed.

---

## Building

Requires **Visual Studio 2022** (C++ core tools, x64).

```bat
build.bat            :: Release x64  ->  x64\Release\RAMstain.exe
build.bat Debug      :: Debug  x64  ->  x64\Debug\RAMstain.exe
```

Or in Visual Studio: open `RAMstain.sln` → select **Release | x64** → Build.

**Versioning.** Every build bumps the minor version (1.1.0 → 1.2.0 → …).
A pre-build step runs `scripts\bump-version.ps1`, which rewrites
`src\version.h`. That header feeds the EXE's version resource, the version in
the app footer and the `Tool:` line in `.meta`. To change the major version or
reset the minor, edit the numbers in `src\version.h`; the next build continues
from there. The bump happens before compiling, so a failed build still uses up
a number.

### Publishing a GitHub Release

```bat
release.bat          :: build, commit version.h, tag vX.Y.Z, push, publish release
release.bat draft    :: same, but the GitHub Release is created as a draft
```

Requires the [GitHub CLI](https://cli.github.com/) (`gh auth login`) and no
uncommitted changes. The script builds Release x64, computes the SHA-256 of
`RAMstain.exe`, shows a summary and asks for confirmation. It then commits
`src\version.h`, tags `vX.Y.Z`, pushes the branch and tag, and creates the
release with `RAMstain.exe` attached and the SHA-256 in the release notes. If
the build fails or you answer N, `src\version.h` is restored, so the version
number is not used up.

## Running

```
RAMstain.exe
```

1. Choose the output path (default is `RAMstain_<timestamp>.raw` next to the
   EXE). Use **Browse…** to pick a different location.
2. Click **Capture**. RAMstain runs as Administrator (UAC prompt at launch),
   runs the built-in imager, and shows live progress as the image grows.
3. On completion you get a summary dialog (size, time, speed, MD5) and the
   option to open the folder.

### Command line

```
RAMstain.exe "D:\evidence\host1.raw"                  :: pre-fill the save path
RAMstain.exe --driver "C:\tools\go-winpmem-signed.exe" :: use an external imager instead of the built-in one
RAMstain.exe --no-driver                              :: start with the experimental driverless path selected
RAMstain.exe --selftest "C:\out\test.raw"             :: run a 512 MiB synthetic pipeline test
```

The built-in imager is used unless you override it with `--driver <path>` or
the `RAMSTAIN_WINPMEM` environment variable (checked in that order). Both
accept the Go imager or the classic WinPmem 2.x.

`--selftest` writes a known synthetic 512 MiB image through the same
write → MD5 → sidecar → dialog pipeline as the driverless path. It is a way to
verify the tool, disk, and MD5 path work end-to-end **without** capturing real
memory. The `.meta` sidecar is clearly marked `SELF-TEST synthetic source`.

---

## Capture methods

**WinPmem driver (default).** Reading physical memory on Windows requires
kernel code, so the supported method is the signed WinPmem driver. The
WinPmem imager (2.0.1, signed by Velocidex) is embedded in `RAMstain.exe`. On
the first driver-mode capture it is written to `%TEMP%\RAMstain-<pid>\`, a
folder whose permissions allow only Administrators and SYSTEM, so a
non-elevated process cannot replace the file before RAMstain runs it. The
folder is deleted when RAMstain closes (also on logoff/shutdown), and folders
left behind by a crashed instance are removed at the next start. During a
capture the imager creates a temporary driver service, loads the driver,
writes the image, and removes the service again. RAMstain also runs the
imager's unload command afterwards as a safety net. Both the Go imager
(`go-winpmem`, `acquire <file>`) and the classic C++ WinPmem 2.x
(`winpmem <file>`) are supported. RAMstain reads the imager's `--help` output
to tell them apart and passes the matching arguments. Progress is shown as the
image file grows, followed by a progress readout while the MD5 is computed. Security products or
driver-blocking policies (e.g. HVCI / the vulnerable-driver blocklist) can
prevent the driver from loading; check Event Viewer if a capture produces no
image.

**Driverless (experimental).** Unticking **Use WinPmem driver** (or passing
`--no-driver`) tries `OpenProcess` on PID -1 followed by `ReadProcessMemory`.
This is **not** a documented Windows API. On Windows 11 build 26200,
`OpenProcess(-1)` fails with error 87 (`ERROR_INVALID_PARAMETER`), exactly the
same error Windows returns for any process ID that does not exist. No Windows
version is known where this path captures memory. It is kept only so it can be
tested on other systems.

---

## Repository layout

```
RAMstain.sln            Visual Studio solution
RAMstain.vcxproj        project (v143 / x64, static CRT, UAC + themed manifest)
build.bat               MSBuild wrapper (app + local tools)
release.bat             build + tag + publish a GitHub Release (SHA-256 in notes)
src/
  RAMstain.cpp          the entire application (UI + capture engine)
  md5.h                 small self-contained MD5 (for capture integrity only)
  legal.h               Disclaimer / Privacy Policy / Terms of Use text
  ramstain.rc           resources (icon, version info, embedded WinPmem + license)
  version.h             version numbers (rewritten by scripts\bump-version.ps1 each build)
  RAMstain.ico          app icon
  RAMstain.manifest     DPI awareness + Common Controls v6 (UAC requireAdministrator is set in RAMstain.vcxproj)
scripts/
  bump-version.ps1      pre-build step: increments the minor version
third_party/winpmem/
  winpmem_x64.exe       signed WinPmem 2.0.1 imager, embedded into RAMstain.exe
  LICENSE               WinPmem's Apache 2.0 license (also embedded, shown in Terms of Use)
  README.md             provenance: version, signer, SHA-256, how to update
.gitignore              excludes build output, captures (*.raw/*.meta), notes
```

`test/` and `tools/` (diagnostics) are intentionally **not** committed — they
contain local captures and helper scripts.

---

## Output example

`host1.raw.meta`:

```
RAMstain capture metadata
=========================
Image:       D:\evidence\host1.raw
Host:        WS-FORENSICS-01
OS:          Windows 10.0 build 26200
Kernel:      NT 10.0.26200
Captured:    20260928_163614 (local time)
Size:        34359738368 bytes
Pages:       8388608 x 4096 bytes
MD5:         2ea471360b0e7eecd12e9f61a5d2649c
Tool:        RAMstain 1.0.0
Method:      WinPmem kernel driver (Velocidex signed driver)
```

---

## Third-party software

RAMstain embeds the [WinPmem](https://github.com/Velocidex/WinPmem) memory
imager, Copyright 2012 Michael Cohen, licensed under the
[Apache License 2.0](third_party/winpmem/LICENSE). The full license text is
shown in the app under **Terms of Use → Third-party software**.

## Legal

RAMstain is provided **as is** for use by qualified professionals on systems
they are legally authorized to access. Use of this tool to capture memory
without proper authorization may be unlawful. This is not legal advice.

The full texts are embedded in the app (footer → **Disclaimer**, **Privacy
Policy**, **Terms of Use**) and maintained in [`src/legal.h`](src/legal.h).
Review them — and the source — with a qualified lawyer before public
distribution.

## Privacy

RAMstain collects nothing and transmits nothing. The only confidential data
involved is the memory image you create, which you write locally and control
entirely. Memory images can contain credentials, keys, and personal data —
treat them as highly sensitive.

## License

Not yet specified. See the legal documents above.
