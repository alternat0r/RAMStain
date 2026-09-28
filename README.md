# RAMstain

A compact, offline **physical memory (RAM) capture** tool for Windows, written
in C++ (Win32, zero runtime dependencies) for forensics and incident response.

One goal: get a memory image off a machine **without** the friction of most
commercial/cloud capture tools — **no account, no email, no phone number, no
username, no download registration, no network connection.** RAMstain is a
single EXE that you run and that writes the dump straight to a path you choose.

---

## What it does

RAMstain captures the entire contents of physical RAM using the **Win32
Physical Memory Handle API** (`OpenProcess` on the physical-memory
pseudo-process + `ReadProcessMemory`). It is the same driverless technique
used by WinPMEM's raw mode — no kernel driver, no service, no install.

For each capture it produces two files in the location you specify:

| File | Description |
|------|-------------|
| `<name>.raw`  | The physical memory image, 4 KiB page-aligned. |
| `<name>.meta` | An evidence sidecar: image path, host name, OS + kernel build, capture timestamp, byte size, page count, MD5 digest, tool version, and method. |

A running **MD5** digest is computed as the image is streamed to disk (the same
convention WinPMEM uses for integrity), and is written to both the completion
dialog and the `.meta` sidecar.

## Key properties

- **Single self-contained EXE.** Statically linked (no VC++ runtime / MFC /
  redistributable required). ~220 KB.
- **Offline by design.** No network calls, no telemetry, no update downloads.
- **Runs as Administrator** (required to read physical memory).
- **Progress + Stop.** Live progress bar; the **Close** button becomes **Stop**
  during a capture, letting you cancel cleanly (a partial image + sidecar is
  kept and marked as such).
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
build.cmd            :: Release x64  ->  x64\Release\RAMstain.exe
build.cmd Debug      :: Debug  x64  ->  x64\Debug\RAMstain.exe
```

Or in Visual Studio: open `RAMstain.sln` → select **Release | x64** → Build.

## Running

```
RAMstain.exe
```

1. Choose the output path (default is `RAMstain_<timestamp>.raw` next to the
   EXE). Use **Browse…** to pick a different location.
2. Click **Capture**. RAMstain self-elevates (UAC) and streams the image to
   disk, showing live progress.
3. On completion you get a summary dialog (size, time, speed, MD5) and the
   option to open the folder.

### Command line

```
RAMstain.exe "D:\evidence\host1.raw"     :: pre-fill the save path
RAMstain.exe --selftest "C:\out\test.raw":: run a 512 MiB synthetic pipeline test
```

`--selftest` writes a known synthetic 512 MiB image through the exact same
write → MD5 → sidecar → dialog pipeline used for real captures. It is a way to
verify the tool, disk, and MD5 path work end-to-end **without** capturing real
memory (useful on machines where the OS blocks physical-memory reads — see
below). The `.meta` sidecar is clearly marked `SELF-TEST synthetic source`.

---

## Platform compatibility (important)

The driverless physical-memory handle API works on **standard Windows 10** and
**Windows 11 (23H2 and earlier)** when run as Administrator.

Starting with certain hardened Windows 11 builds (reported on **24H2/25H2**,
e.g. build 26200), Microsoft restricts `OpenProcess` on the physical-memory
pseudo-process even for an elevated token. On those systems RAMstain **will not
be able to capture physical memory** — it detects this and explains it, rather
than failing silently. Options in that case:

1. Run RAMstain on a Windows 10 / 11 (≤23H2) host.
2. Use a kernel-driver method (e.g. WinPMEM with a signed driver, or DumpIt) —
   requires a reboot and installing a signed kernel driver.
3. Capture inside a VM and image the guest's RAM.

You can check whether a given machine is affected simply by running
`RAMstain.exe` and clicking Capture: the error message will tell you if the OS
blocked physical-memory access (error 87).

---

## Repository layout

```
RAMstain.sln            Visual Studio solution
RAMstain.vcxproj        project (v143 / x64, static CRT, UAC + themed manifest)
build.cmd               one-line MSBuild wrapper
src/
  RAMstain.cpp          the entire application (UI + capture engine)
  md5.h                 small self-contained MD5 (for capture integrity only)
  legal.h               Disclaimer / Privacy Policy / Terms of Use text
  ramstain.rc           resources (icon, version info)
  RAMstain.ico          app icon
  RAMstain.manifest     DPI awareness + Common Controls v6 (UAC requireAdministrator is set in RAMstain.vcxproj)
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
Host:        KAMIL-MY
OS:          Windows 10.0 build 26200
Kernel:      NT 10.0.26200
Captured:    20260928_163614 (local time)
Size:        34359738368 bytes
Pages:       8388608 x 4096 bytes
MD5:         2ea471360b0e7eecd12e9f61a5d2649c
Tool:        RAMstain 1.0.0
Method:      Win32 Physical Memory Handle API (no driver, no network)
```

---

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
