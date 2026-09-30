# WinPmem (embedded)

`winpmem_x64.exe` is embedded into `RAMstain.exe` as a resource
(`IDR_WINPMEM` in `src/ramstain.rc`) and is the default capture method.
RAMstain writes it to a temporary, Administrators-only folder
(`%TEMP%\RAMstain-<pid>\`) the first time a driver-mode capture runs, and
deletes that folder when RAMstain closes.

| | |
|---|---|
| Project   | WinPmem - https://github.com/Velocidex/WinPmem |
| Version   | 2.0.1 (classic C++ imager, "Oct 13 2020" build) |
| Signed by | Velocidex Innovations (Sectigo RSA Code Signing CA), signature valid |
| SHA-256   | `a4d516b6fcaf3b5b1d4ee709ce86f8eabf1d8028b3a83101479b7568b933d21b` |
| License   | Apache License 2.0 - see `LICENSE` (copied verbatim from the WinPmem repository) |

`LICENSE` is also embedded (`IDR_WINPMEM_LICENSE`) and shown in the app under
**Terms of Use → Third-party software**, as Apache 2.0 requires.

To update the embedded imager: replace `winpmem_x64.exe`, check its signature
(`Get-AuthenticodeSignature`), update the version and SHA-256 above, and
rebuild. If you switch to the Go imager (`go-winpmem`), RAMstain's
command-line detection (`DetectImagerKind`) handles its different syntax.
