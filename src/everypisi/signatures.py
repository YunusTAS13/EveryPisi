from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .errors import UnsupportedFormatError


def verify_detached_signature(package: Path, signature: Path, keyring: Path) -> str:
    """Verify a detached OpenPGP signature against an explicit keyring."""
    verifier = shutil.which("gpgv")
    if not verifier:
        raise UnsupportedFormatError("detached OpenPGP verification requires gpgv")
    package = package.expanduser().resolve()
    signature = signature.expanduser().resolve()
    keyring = keyring.expanduser().resolve()
    if not package.is_file():
        raise UnsupportedFormatError(f"signed package does not exist: {package}")
    if not signature.is_file():
        raise UnsupportedFormatError(f"detached signature does not exist: {signature}")
    if not keyring.is_file():
        raise UnsupportedFormatError(f"signature keyring does not exist: {keyring}")
    result = subprocess.run(
        [verifier, "--status-fd", "1", "--keyring", str(keyring),
         str(signature), str(package)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    valid = result.returncode == 0 and any(
        line.startswith("[GNUPG:] VALIDSIG ") for line in result.stdout.splitlines()
    )
    if not valid:
        detail = (result.stderr or "").strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise UnsupportedFormatError(f"detached OpenPGP signature verification failed{suffix}")
    return "verified"


def verify_debsig_signature(package: Path, policies_dir: Path, keyrings_dir: Path,
                            root: Path | None = None) -> str:
    """Verify an embedded Debian signature through debsig-verify policies."""
    verifier = shutil.which("debsig-verify")
    if not verifier:
        raise UnsupportedFormatError("Debian embedded signature verification requires debsig-verify")
    package = package.expanduser().resolve()
    policies_dir = policies_dir.expanduser().resolve()
    keyrings_dir = keyrings_dir.expanduser().resolve()
    if not package.is_file():
        raise UnsupportedFormatError(f"signed package does not exist: {package}")
    if not policies_dir.is_dir():
        raise UnsupportedFormatError(f"Debian debsig policies directory does not exist: {policies_dir}")
    if not keyrings_dir.is_dir():
        raise UnsupportedFormatError(f"Debian debsig keyrings directory does not exist: {keyrings_dir}")
    command = [verifier, "--quiet", "--policies-dir", str(policies_dir),
               "--keyrings-dir", str(keyrings_dir)]
    if root is not None:
        root = root.expanduser().resolve()
        if not root.is_dir():
            raise UnsupportedFormatError(f"Debian debsig root directory does not exist: {root}")
        command.extend(["--root", str(root)])
    command.append(str(package))
    result = subprocess.run(command, capture_output=True, text=True,
                            check=False, timeout=30)
    if result.returncode:
        detail = (result.stderr or "").strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise UnsupportedFormatError(f"Debian embedded signature verification failed{suffix}")
    return "verified"
