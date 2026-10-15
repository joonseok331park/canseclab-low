"""Windows sharing errors must not leave a partially replaced output pair."""
import ctypes
from ctypes import wintypes
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> None:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    exe = str(Path(sys.argv[1]).resolve())
    working = Path.cwd().resolve()
    with tempfile.TemporaryDirectory(prefix="profile-transaction-", dir=working) as temporary:
        directory = Path(temporary).resolve()
        if not directory.is_relative_to(working):
            raise RuntimeError("Test directory escaped the build directory")
        (directory / "input.log").write_bytes(b"(1.000000) vcan0 100#0010\n")
        for existing_baseline in (False, True):
            baseline = directory / "baseline.ini"
            summary = directory / "summary.md"
            if existing_baseline:
                baseline.write_bytes(b"previous baseline\n")
            summary.write_bytes(b"previous summary\n")
            handle = create(str(summary), 0x80000000, 1, None, 3, 128, None)
            if handle == wintypes.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                result = subprocess.run([exe, "--in", "input.log", "--out", "baseline.ini",
                                         "--summary", "summary.md"], cwd=directory,
                                        capture_output=True, text=True)
                if result.returncode != 1 or "error:" not in result.stderr:
                    raise RuntimeError(f"Locked second output should fail: {result}")
                if summary.read_bytes() != b"previous summary\n":
                    raise RuntimeError("Locked summary was modified")
                if existing_baseline:
                    if baseline.read_bytes() != b"previous baseline\n":
                        raise RuntimeError("Previous baseline was not restored")
                elif baseline.exists():
                    raise RuntimeError("New baseline survived a failed output pair")
                if list(directory.glob(".cansec-profile-*")):
                    raise RuntimeError("Successful rollback left staging files")
            finally:
                close(handle)
            print(f"PASS: second-output sharing error rolls back baseline (existing={existing_baseline})")


if __name__ == "__main__":
    main()
