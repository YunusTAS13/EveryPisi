from __future__ import annotations

import bz2
import gzip
import lzma
import shutil
import subprocess
import io

from .errors import ResourceLimitError, UnsupportedFormatError
from .util import MAX_EXPANDED_BYTES


def decompress(data: bytes, *, hint: str = "", max_output: int = MAX_EXPANDED_BYTES) -> bytes:
    """Decompress a package payload without invoking a shell."""
    if len(data) > max_output:
        raise ResourceLimitError("compressed input exceeds the decompression safety limit")
    lower_hint = hint.lower()
    if data.startswith(b"\x1f\x8b") or lower_hint.endswith((".gz", ".gzip")):
        return _bounded_stream(gzip.GzipFile(fileobj=io.BytesIO(data)), max_output)
    if data.startswith(b"BZh") or lower_hint.endswith((".bz2", ".bzip2")):
        return _bounded_stream(bz2.BZ2File(io.BytesIO(data)), max_output)
    if data.startswith(bytes.fromhex("fd 37 7a 58 5a 00")) or lower_hint.endswith((".xz", ".lzma")):
        return _bounded_stream(lzma.LZMAFile(io.BytesIO(data)), max_output)
    if data.startswith(bytes.fromhex("28 b5 2f fd")) or lower_hint.endswith(".zst"):
        return _external(data, ("zstd", "unzstd"), ("-q", "-d", "-c"), "zstd", max_output)
    if data.startswith(bytes.fromhex("04 22 4d 18")) or lower_hint.endswith(".lz4"):
        return _external(data, ("lz4", "unlz4"), ("-q", "-d", "-c"), "lz4", max_output)
    if data.startswith(b"LZIP") or lower_hint.endswith(".lz"):
        return _external(data, ("lzip",), ("-d", "-c"), "lzip", max_output)
    if data.startswith(b"\x89LZO") or lower_hint.endswith(".lzo"):
        return _external(data, ("lzop",), ("-d", "-c"), "lzop", max_output)
    return data


def _bounded_stream(stream, max_output: int) -> bytes:
    output = bytearray()
    try:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > max_output:
                raise ResourceLimitError("decompressed payload exceeds the safety limit")
    finally:
        stream.close()
    return bytes(output)


def _external(data: bytes, commands: tuple[str, ...], arguments: tuple[str, ...], label: str,
              max_output: int) -> bytes:
    command = next((shutil.which(item) for item in commands if shutil.which(item)), None)
    if not command:
        raise UnsupportedFormatError(f"package uses {label} compression; install a {label} decompressor")
    process = subprocess.Popen([command, *arguments], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    try:
        process.stdin.write(data)
        process.stdin.close()
        output = bytearray()
        while True:
            chunk = process.stdout.read(1024 * 1024)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > max_output:
                raise ResourceLimitError("decompressed payload exceeds the safety limit")
        detail = process.stderr.read().decode("utf-8", "replace")
        return_code = process.wait()
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()
    if return_code:
        raise UnsupportedFormatError(detail or f"{label} decompression failed")
    return bytes(output)
