"""Install the verified selector patch through the standard Windows UAC prompt."""

import ctypes
import subprocess
import sys
import traceback
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import patch_selector

ROOT = Path(__file__).resolve().parent
LOG = ROOT / "diagnostics" / "installation.log"


def request_elevation() -> None:
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.ShellExecuteW.argtypes = (
        [ctypes.c_void_p] + [ctypes.c_wchar_p] * 4 + [ctypes.c_int]
    )
    shell.ShellExecuteW.restype = ctypes.c_void_p
    arguments = subprocess.list2cmdline([str(Path(__file__).resolve()), "--elevated"])
    result = shell.ShellExecuteW(None, "runas", sys.executable, arguments, str(ROOT), 0)
    if not result or result <= 32:
        raise OSError(f"Windows did not start the elevated installer (code {result}).")
    print("Elevated installer launched. Result log:", LOG)


def main() -> None:
    if sys.platform != "win32":
        raise OSError("This installer requires Windows.")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        if "--elevated" in sys.argv:
            raise PermissionError("Administrator elevation was not granted.")
        request_elevation()
        return
    LOG.parent.mkdir(exist_ok=True)
    with (
        LOG.open("w", encoding="utf-8") as log,
        redirect_stdout(log),
        redirect_stderr(log),
    ):
        try:
            patch_selector.main(["--apply"])
        except Exception:
            traceback.print_exc()
            raise


if __name__ == "__main__":
    main()
