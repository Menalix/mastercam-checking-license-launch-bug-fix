# Mastercam stuck on “Checking License”

Opening an `.emcam` file can leave Mastercam waiting for an invisible agreement window. The file launcher, `McamVersionSelector.exe`, starts Mastercam with `SW_HIDE` instead of `SW_SHOWNORMAL`.

I've tested this on **Mastercam 2026, build 28.0.0.0**. It's a proof of concept, shared in the hope that Mastercam will fix the bug officially.

> **Before using this:** the patch modifies a signed Mastercam executable and invalidates its digital signature. Modifying vendor binaries may violate your EULA or affect your license or support rights. Check your terms or ask Mastercam first. This isn't an official or supported fix.

![Mastercam stuck on Checking License](images/checking-license.png)

## Why does restarting sometimes help?

The reminder counter advances before the agreement opens. Killing the hung process can leave that advance saved, so the next launch may skip the reminder and start normally.

Opening Mastercam directly also avoids the file selector's hidden-start setting. Without the patch, try starting Mastercam first, then opening your `.emcam` file from inside it.

## Patch the launcher

Install Python 3, download this repo, then run:

```powershell
py -m pip install -r requirements.txt
py install_patch.py
```

Approve the administrator prompt. The patch changes one byte so the agreement can appear normally. It keeps an original backup beside the launcher.

Check: `py patch_selector.py`

Undo, from an administrator terminal:

```powershell
py patch_selector.py --restore "PATH_TO_ORIGINAL_BACKUP"
```

Re-run after updates. Unsupported code layouts are refused. Modifying the launcher invalidates its vendor signature; restoring the original backup restores it.

## Registry workaround

Already accepted the agreement? You can skip the reminders instead:

1. Open `regedit`.
2. Go to `HKEY_CURRENT_USER\Software\CNC Software\Mastercam 2026`.
3. Set the DWORD (32-bit) value `EULA count` to **11, Decimal**.

Or import [skip-eula-reminders-2026.reg](skip-eula-reminders-2026.reg). Export the key first for a backup.

This applies to the current user and version. It skips reminders, rather than fixing hidden windows. It won't fix unrelated licensing hangs.

## Patch details

In selector build 28.0.0.0, file offset `0xFEF8` changes from `00` to `01`:

```asm
mov dword ptr [rsp+28h], 0  ; SW_HIDE
; becomes
mov dword ptr [rsp+28h], 1  ; SW_SHOWNORMAL
```

The patcher verifies the `ShellExecuteW` call and its arguments; it doesn't blindly reuse that offset.

Unofficial PoC. No Mastercam binaries or license-check changes included.
