from __future__ import annotations

import base64
import re
import stat
import struct
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..errors import ResourceLimitError, UnsafeArchiveError, UnsupportedFormatError
from ..compression import decompress
from ..model import DependencyAtom, DependencyGroup, ParsedPackage
from ..util import (MAX_ARCHIVE_MEMBERS, check_input_size, ensure_entry_absent, ensure_inside,
                    ensure_safe_parent, safe_relative_path, scan_payload)
from .base import (PackageParser, normalize_pisi_release, normalize_pisi_version,
                   parse_script)


RPM_LEAD_MAGIC = bytes.fromhex("ed ab ee db")
RPM_HEADER_MAGIC = bytes.fromhex("8e ad e8 01")

# RPM tag numbers from the public rpm.org tag table.
TAG = {
    "name": 1000, "version": 1001, "release": 1002, "summary": 1004,
    "description": 1005, "size": 1009, "license": 1014, "url": 1020,
    "arch": 1022, "prein": 1023, "postin": 1024, "preun": 1025,
    "postun": 1026, "filesizes": 1028, "filemodes": 1030,
    "filedigests": 1035, "fileusername": 1039, "filegroupname": 1040,
    "providename": 1047, "requireshflags": 1048, "requirename": 1049,
    "requireversion": 1050, "conflictflags": 1053, "conflictname": 1054,
    "conflictversion": 1055, "dirindexes": 1116,
    "obsoletename": 1090, "obsoleteflags": 1114, "obsoleteversion": 1115,
    "basenames": 1117, "dirnames": 1118, "payloadcompressor": 1125,
    "filecaps": 5010, "filedigestalgo": 5011, "payloadsha256": 5092, "payloadsha256alt": 5097,
    "rpmformat": 5114, "payloadsha512": 5121, "payloadsha512alt": 5122,
    "fileuids": 1031, "filegids": 1032, "filelinktos": 1036,
    "fileinodes": 1096, "longfilesizes": 5008,
}

RPM_FLAG_LESS = 0x02
RPM_FLAG_GREATER = 0x04
RPM_FLAG_EQUAL = 0x08
RPM_SENSE_PRETRANS = 1 << 7
RPM_SENSE_INTERP = 1 << 8
RPM_SENSE_SCRIPT_PRE = 1 << 9
RPM_SENSE_SCRIPT_POST = 1 << 10
RPM_SENSE_SCRIPT_PREUN = 1 << 11
RPM_SENSE_SCRIPT_POSTUN = 1 << 12
RPM_SENSE_SCRIPT_VERIFY = 1 << 13
RPM_SENSE_TRIGGER = (1 << 16) | (1 << 17) | (1 << 18) | (1 << 25)
RPM_SENSE_TRANS = (1 << 5) | (1 << 20) | (1 << 21)
RPM_SENSE_NON_RUNTIME = (RPM_SENSE_PRETRANS | RPM_SENSE_INTERP | RPM_SENSE_SCRIPT_PRE
                         | RPM_SENSE_SCRIPT_POST | RPM_SENSE_SCRIPT_PREUN | RPM_SENSE_SCRIPT_POSTUN
                         | RPM_SENSE_SCRIPT_VERIFY | RPM_SENSE_TRIGGER | RPM_SENSE_TRANS)


class RpmHeader:
    def __init__(self, tags: dict[int, object], end: int, start: int):
        self.tags = tags
        self.end = end
        self.start = start

    def get(self, name: str, default=None):
        value = self.tags.get(TAG[name], default)
        if isinstance(value, list) and len(value) == 1:
            return value[0]
        return value


def _read_header(blob: bytes, offset: int) -> RpmHeader:
    if blob[offset:offset + 4] != RPM_HEADER_MAGIC:
        raise UnsupportedFormatError(f"invalid RPM header at offset {offset}")
    if len(blob) < offset + 16:
        raise UnsupportedFormatError("truncated RPM header")
    count, data_size = struct.unpack(">II", blob[offset + 8:offset + 16])
    if count > MAX_ARCHIVE_MEMBERS:
        raise ResourceLimitError("RPM header contains too many entries")
    index_start = offset + 16
    data_start = index_start + count * 16
    data_end = data_start + data_size
    if data_end > len(blob):
        raise UnsupportedFormatError("RPM header data exceeds file")
    data = blob[data_start:data_end]
    tags: dict[int, object] = {}
    for index in range(count):
        tag, kind, relative_offset, item_count = struct.unpack(">IIII", blob[index_start + index * 16:index_start + (index + 1) * 16])
        if tag in tags:
            raise UnsupportedFormatError(f"duplicate RPM header tag: {tag}")
        if relative_offset > len(data):
            raise UnsupportedFormatError(f"invalid RPM header tag offset: {tag}")
        tags[tag] = _decode_rpm_value(data, relative_offset, kind, item_count)
    # The signature header is followed by alignment padding, while the main
    # header is immediately followed by the compressed CPIO payload.  The
    # caller aligns only when moving from signature to main header.
    return RpmHeader(tags, data_end, offset)


def _first_tag(tags: dict[int, object], tag: int):
    value = tags.get(tag)
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _safe_rpm_path(dirname: str, basename: str) -> str:
    """RPM stores compressed paths with absolute dirname components."""
    return safe_relative_path(f"{dirname}{basename}".lstrip("/"))


def _verify_rpm_digests(blob: bytes, signature: RpmHeader, header: RpmHeader, payload: bytes) -> dict[str, str]:
    integrity: dict[str, str] = {}

    checks = (
        (signature.tags, 269, hashlib.sha1, blob[header.start:header.end], "header-sha1"),
        (signature.tags, 273, hashlib.sha256, blob[header.start:header.end], "header-sha256"),
        (signature.tags, 272, hashlib.sha256, blob[header.start:header.end], "header-sha256-v6"),
        (signature.tags, 279, hashlib.sha3_256, blob[header.start:header.end], "header-sha3-256-v6"),
        (signature.tags, 1004, hashlib.md5, blob[header.start:], "header-payload-md5"),
        (signature.tags, 261, hashlib.md5, blob[header.start:], "header-payload-md5-v6"),
        (header.tags, 5092, hashlib.sha256, payload, "compressed-payload-sha256"),
        (header.tags, 5121, hashlib.sha512, payload, "compressed-payload-sha512"),
        (header.tags, 5123, hashlib.sha3_256, payload, "compressed-payload-sha3-256"),
    )
    for tags, tag, algorithm, content, label in checks:
        expected = _first_tag(tags, tag)
        if expected in (None, b"", ""):
            continue
        actual = algorithm(content).hexdigest()
        if isinstance(expected, bytes):
            expected_text = expected.hex()
        else:
            expected_text = str(expected).strip().lower()
        if actual != expected_text:
            raise UnsupportedFormatError(f"RPM {label} verification failed")
        integrity[label] = "verified"
    return integrity


def _verify_rpm_openpgp(blob: bytes, signature: RpmHeader, header: RpmHeader, keyring: Path) -> str:
    """Verify embedded RPM OpenPGP signatures with a caller-supplied keyring."""
    verifier = shutil.which("gpgv")
    if not verifier:
        raise UnsupportedFormatError("RPM OpenPGP verification requires gpgv")
    keyring = keyring.expanduser().resolve()
    if not keyring.is_file():
        raise UnsupportedFormatError(f"RPM keyring does not exist: {keyring}")
    header_signature = _first_tag(signature.tags, 268) or _first_tag(signature.tags, 267)
    header_payload_signature = (
        _first_tag(signature.tags, 1002) or _first_tag(signature.tags, 1005)
        or _first_tag(signature.tags, 259) or _first_tag(signature.tags, 262)
    )
    v6_signatures = signature.tags.get(278, [])
    if isinstance(v6_signatures, str):
        v6_signatures = [v6_signatures]
    if not header_signature and not header_payload_signature and not v6_signatures:
        raise UnsupportedFormatError("RPM contains no supported OpenPGP signature tag")
    checks: list[tuple[bytes, bytes, str]] = []
    if header_signature:
        checks.append((header_signature, blob[header.start:header.end], "header"))
    for index, encoded in enumerate(v6_signatures):
        try:
            decoded = base64.b64decode(str(encoded), validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise UnsupportedFormatError(f"RPM v6 OpenPGP signature {index} is invalid base64") from exc
        checks.append((decoded, blob[header.start:header.end], f"v6-header-{index}"))
    if header_payload_signature:
        checks.append((header_payload_signature, blob[header.start:], "header+payload"))
    with tempfile.TemporaryDirectory(prefix="everypisi-rpm-signature-") as directory:
        base = Path(directory)
        for index, (signature_bytes, signed_data, scope) in enumerate(checks):
            if not isinstance(signature_bytes, bytes):
                raise UnsupportedFormatError(f"RPM {scope} OpenPGP signature has an invalid type")
            signature_path = base / f"signature-{index}.pgp"
            data_path = base / f"signed-{index}.bin"
            signature_path.write_bytes(signature_bytes)
            data_path.write_bytes(signed_data)
            result = subprocess.run(
                [verifier, "--status-fd", "1", "--keyring", str(keyring),
                 str(signature_path), str(data_path)],
                capture_output=True, text=True, check=False, timeout=30,
            )
            valid = result.returncode == 0 and any(
                line.startswith("[GNUPG:] VALIDSIG ") for line in result.stdout.splitlines()
            )
            if not valid:
                detail = (result.stderr or "").strip().splitlines()
                suffix = f": {detail[-1]}" if detail else ""
                raise UnsupportedFormatError(f"RPM {scope} OpenPGP signature verification failed{suffix}")
    return "verified"


def _verify_rpm_file_digests(header: RpmHeader, root: Path, source_metadata: dict[str, dict[str, int]]) -> str:
    digests = _as_list(header.get("filedigests", []))
    if not digests:
        return "not-present"
    directories = _as_list(header.get("dirnames", []))
    basenames = _as_list(header.get("basenames", []))
    dirindexes = _as_list(header.get("dirindexes", []))
    if not (len(digests) == len(basenames) == len(dirindexes)):
        raise UnsupportedFormatError("RPM file digest metadata has inconsistent lengths")
    algorithms = {
        1: hashlib.md5,
        2: hashlib.sha1,
        8: hashlib.sha256,
        9: hashlib.sha384,
        10: hashlib.sha512,
    }
    algorithm_id = header.get("filedigestalgo", 1)
    try:
        algorithm = algorithms[int(algorithm_id)]
    except (KeyError, TypeError, ValueError) as exc:
        raise UnsupportedFormatError(f"unsupported RPM file digest algorithm: {algorithm_id}") from exc
    checked = 0
    for index, expected in enumerate(digests):
        expected = str(expected).strip().lower()
        if not expected or not set(expected) - {"0"}:
            continue
        dirname_index = int(dirindexes[index])
        if dirname_index >= len(directories):
            raise UnsupportedFormatError(f"invalid RPM file digest directory index: {dirname_index}")
        rel = _safe_rpm_path(str(directories[dirname_index]), str(basenames[index]))
        target = root / rel
        if rel not in source_metadata or not (target.is_file() or target.is_symlink()):
            raise UnsupportedFormatError(f"RPM file digest references missing payload file: {rel}")
        digest = algorithm()
        if target.is_symlink():
            digest.update(os.readlink(target).encode())
        else:
            with target.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        if digest.hexdigest().lower() != expected:
            raise UnsupportedFormatError(f"RPM file digest verification failed: {rel}")
        checked += 1
    return f"verified:{checked}"


def _decode_rpm_value(data: bytes, start: int, kind: int, count: int):
    if kind in (6, 9):  # STRING and I18NSTRING
        values = []
        cursor = start
        for _ in range(count):
            end = data.find(b"\0", cursor)
            if end < 0:
                raise UnsupportedFormatError("unterminated RPM string tag")
            values.append(data[cursor:end].decode("utf-8", "replace"))
            cursor = end + 1
        return values
    if kind == 8:  # STRING_ARRAY
        return _decode_rpm_value(data, start, 6, count)
    widths = {2: (1, ">B"), 3: (2, ">H"), 4: (4, ">I"), 5: (8, ">Q")}
    if kind in widths:
        width, fmt = widths[kind]
        end = start + width * count
        if end > len(data):
            raise UnsupportedFormatError("truncated RPM integer tag")
        return [struct.unpack(fmt, data[start + i * width:start + (i + 1) * width])[0] for i in range(count)]
    if kind == 7:  # BIN
        if start + count > len(data):
            raise UnsupportedFormatError("truncated RPM binary tag")
        return data[start:start + count]
    if kind == 0:
        return None
    raise UnsupportedFormatError(f"unsupported RPM header data type: {kind}")


def _decompress_payload(payload: bytes, compressor: str) -> bytes:
    name = (compressor or "gzip").lower()
    if name in ("none", "identity"):
        return payload
    try:
        hint = {
            "zstd:chunked": "payload.zst",
            "zstd": "payload.zst",
            "lz4": "payload.lz4",
            "lzip": "payload.lz",
            "lzop": "payload.lzo",
        }.get(name, name)
        return decompress(payload, hint=hint)
    except UnsupportedFormatError:
        raise
    except (OSError, EOFError, ValueError) as exc:
        raise UnsupportedFormatError(f"unsupported RPM payload compressor {compressor}: {exc}") from exc


def _read_newc(payload: bytes, destination: Path, warnings: list[str], source_metadata: dict[str, dict[str, int]] | None = None,
               metadata_flags: list[str] | None = None) -> None:
    source_metadata = source_metadata if source_metadata is not None else {}
    metadata_flags = metadata_flags if metadata_flags is not None else []
    cursor = 0
    inode_paths: dict[int, Path] = {}
    pending_hardlinks: list[tuple[Path, int, int]] = []
    seen: set[str] = set()
    member_count = 0
    while cursor + 110 <= len(payload):
        member_count += 1
        if member_count > MAX_ARCHIVE_MEMBERS:
            raise ResourceLimitError("RPM CPIO payload contains too many members")
        magic = payload[cursor:cursor + 6]
        if magic not in (b"070701", b"070702"):
            raise UnsupportedFormatError(f"unsupported CPIO payload format: {magic!r}")
        values = [int(payload[cursor + start:cursor + start + 8], 16) for start in range(6, 110, 8)]
        inode, mode, uid, gid, nlink, mtime, file_size, _, _, _, _, name_size, check = values
        cursor += 110
        if name_size < 1:
            raise UnsupportedFormatError("invalid CPIO filename size")
        if cursor + name_size > len(payload):
            raise UnsupportedFormatError("truncated CPIO filename")
        raw_name = payload[cursor:cursor + name_size - 1]
        cursor += name_size
        cursor = (cursor + 3) & ~3
        name = raw_name.decode("utf-8", "surrogateescape")
        if name == "TRAILER!!!":
            if file_size:
                raise UnsupportedFormatError("CPIO trailer has unexpected data")
            _resolve_pending_hardlinks(pending_hardlinks, inode_paths, destination)
            return
        rel = safe_relative_path(name)
        if not rel:
            continue
        if rel in seen:
            raise UnsupportedFormatError(f"duplicate CPIO member: {rel}")
        seen.add(rel)
        target = destination / rel
        ensure_safe_parent(destination, target)
        source_metadata[rel] = {"uid": uid, "gid": gid, "mode": stat.S_IMODE(mode)}
        file_type = stat.S_IFMT(mode)
        if cursor + file_size > len(payload):
            raise UnsupportedFormatError("truncated CPIO file data")
        content = payload[cursor:cursor + file_size]
        cursor += file_size
        cursor = (cursor + 3) & ~3
        if magic == b"070702" and (sum(content) & 0xffffffff) != check:
            raise UnsupportedFormatError(f"CPIO CRC verification failed: {rel}")
        if file_type == stat.S_IFDIR:
            if target.is_symlink() or (target.exists() and not target.is_dir()):
                raise UnsafeArchiveError(f"RPM directory collides with non-directory: {rel}")
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(stat.S_IMODE(mode))
        elif file_type == stat.S_IFLNK:
            link_target = content.decode("utf-8", "surrogateescape")
            target.parent.mkdir(parents=True, exist_ok=True)
            ensure_entry_absent(destination, target)
            target.symlink_to(link_target)
        elif file_type == stat.S_IFREG:
            ensure_entry_absent(destination, target)
            target.parent.mkdir(parents=True, exist_ok=True)
            existing = inode_paths.get(inode)
            if existing is not None and file_size == 0 and existing.exists():
                if target.exists() or target.is_symlink():
                    target.unlink()
                target.hardlink_to(existing)
            elif file_size == 0 and nlink > 1 and inode not in inode_paths:
                pending_hardlinks.append((target, inode, stat.S_IMODE(mode)))
            else:
                target.write_bytes(content)
                target.chmod(stat.S_IMODE(mode))
                inode_paths.setdefault(inode, target)
        else:
            warnings.append(f"unsupported CPIO special file skipped: {rel}")
            metadata_flags.append(f"special-file-not-supported:{rel}")
    raise UnsupportedFormatError("CPIO payload lacks trailer")


def _resolve_pending_hardlinks(pending: list[tuple[Path, int, int]], inode_paths: dict[int, Path],
                               destination: Path) -> None:
    for target, inode, mode in pending:
        ensure_safe_parent(destination, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        existing = inode_paths.get(inode)
        if existing is not None and existing.is_file() and not existing.is_symlink():
            target.hardlink_to(existing)
        else:
            # If an archive advertises a shared inode but never supplies a
            # non-empty member, retain a safe empty regular file rather than
            # dropping the path from the manifest.
            target.write_bytes(b"")
            target.chmod(mode)


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _read_stripped(payload: bytes, destination: Path, warnings: list[str], source_metadata: dict[str, dict[str, int]], header: RpmHeader,
                   metadata_flags: list[str] | None = None) -> None:
    metadata_flags = metadata_flags if metadata_flags is not None else []
    """Read RPM's 07070X payload, whose metadata lives in the RPM header."""
    directories = _as_list(header.get("dirnames", []))
    basenames = _as_list(header.get("basenames", []))
    dirindexes = _as_list(header.get("dirindexes", []))
    modes = _as_list(header.get("filemodes", []))
    sizes = _as_list(header.tags.get(TAG["longfilesizes"], header.tags.get(TAG["filesizes"], [])))
    uids = _as_list(header.get("fileuids", []))
    gids = _as_list(header.get("filegids", []))
    links = _as_list(header.get("filelinktos", []))
    inodes = _as_list(header.get("fileinodes", []))
    if not (len(basenames) == len(dirindexes) == len(modes) == len(sizes)):
        raise UnsupportedFormatError("RPM stripped payload has incomplete file metadata")
    cursor = 0
    seen_indexes: set[int] = set()
    seen_paths: set[str] = set()
    inode_paths: dict[int, Path] = {}
    pending_hardlinks: list[tuple[Path, int, int]] = []
    member_count = 0
    while cursor + 14 <= len(payload):
        member_count += 1
        if member_count > MAX_ARCHIVE_MEMBERS:
            raise ResourceLimitError("RPM stripped CPIO payload contains too many members")
        if payload[cursor:cursor + 6] != b"07070X":
            raise UnsupportedFormatError("invalid RPM stripped payload header")
        try:
            index = int(payload[cursor + 6:cursor + 14], 16)
        except ValueError as exc:
            raise UnsupportedFormatError("invalid RPM stripped payload file index") from exc
        cursor += 14
        cursor = (cursor + 3) & ~3
        if index == 0xffffffff:
            _resolve_pending_hardlinks(pending_hardlinks, inode_paths, destination)
            return
        if index >= len(basenames) or index in seen_indexes:
            raise UnsupportedFormatError(f"invalid or duplicate RPM stripped payload index: {index}")
        seen_indexes.add(index)
        dirname_index = int(dirindexes[index])
        if dirname_index >= len(directories):
            raise UnsupportedFormatError(f"invalid RPM directory index: {dirname_index}")
        rel = _safe_rpm_path(str(directories[dirname_index]), str(basenames[index]))
        if not rel:
            raise UnsupportedFormatError("empty RPM stripped payload path")
        if rel in seen_paths:
            raise UnsupportedFormatError(f"duplicate RPM stripped payload path: {rel}")
        seen_paths.add(rel)
        mode = int(modes[index])
        file_type = stat.S_IFMT(mode)
        expected_size = int(sizes[index])
        if file_type in (stat.S_IFDIR, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO):
            content_size = 0
        else:
            content_size = expected_size
        if cursor + content_size > len(payload):
            raise UnsupportedFormatError(f"truncated RPM stripped payload file: {rel}")
        content = payload[cursor:cursor + content_size]
        cursor += content_size
        cursor = (cursor + 3) & ~3
        target = destination / rel
        ensure_safe_parent(destination, target)
        uid = int(uids[index]) if index < len(uids) else 0
        gid = int(gids[index]) if index < len(gids) else 0
        source_metadata[rel] = {"uid": uid, "gid": gid, "mode": stat.S_IMODE(mode)}
        target.parent.mkdir(parents=True, exist_ok=True)
        if file_type == stat.S_IFDIR:
            if target.is_symlink() or (target.exists() and not target.is_dir()):
                raise UnsafeArchiveError(f"RPM stripped directory collides with non-directory: {rel}")
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(stat.S_IMODE(mode))
        elif file_type == stat.S_IFLNK:
            link_target = content.decode("utf-8", "surrogateescape")
            if not link_target and index < len(links):
                link_target = str(links[index])
            ensure_entry_absent(destination, target)
            target.symlink_to(link_target)
        elif file_type == stat.S_IFREG:
            ensure_entry_absent(destination, target)
            inode = int(inodes[index]) if index < len(inodes) else 0
            existing = inode_paths.get(inode) if inode else None
            if existing is not None and content_size == 0 and existing.exists():
                if target.exists() or target.is_symlink():
                    target.unlink()
                target.hardlink_to(existing)
            elif content_size == 0 and inode and inode not in inode_paths:
                pending_hardlinks.append((target, inode, stat.S_IMODE(mode)))
            else:
                target.write_bytes(content)
                target.chmod(stat.S_IMODE(mode))
                if inode:
                    inode_paths.setdefault(inode, target)
        else:
            warnings.append(f"unsupported RPM special file skipped: {rel}")
            metadata_flags.append(f"special-file-not-supported:{rel}")
    raise UnsupportedFormatError("RPM stripped payload lacks trailer")


def _dependency_atoms(names, flags, versions, scope: str = "runtime"):
    names = _as_list(names)
    flags = _as_list(flags)
    versions = _as_list(versions)
    groups = []
    seen = set()
    for index, name in enumerate(names):
        if _unsupported_rpm_relation(name):
            continue
        if name.startswith("rpmlib(") or name.startswith("rtld("):
            continue
        if not name or name in seen:
            continue
        seen.add(name)
        flag = flags[index] if index < len(flags) else 0
        version = versions[index] if index < len(versions) else None
        version = version or None
        if flag & RPM_FLAG_GREATER and flag & RPM_FLAG_EQUAL:
            operator = ">="
        elif flag & RPM_FLAG_LESS and flag & RPM_FLAG_EQUAL:
            operator = "<="
        elif flag & RPM_FLAG_GREATER:
            operator = ">"
        elif flag & RPM_FLAG_LESS:
            operator = "<"
        elif flag & RPM_FLAG_EQUAL:
            operator = "="
        else:
            operator = None
        dependency_scope = "script" if scope == "runtime" and flag & RPM_SENSE_NON_RUNTIME else scope
        groups.append(DependencyGroup((DependencyAtom(name, operator, version, raw=name),), dependency_scope))
    return groups


def _unsupported_rpm_relation(value: str) -> bool:
    """Return whether RPM syntax cannot be represented by a Pisi relation.

    RPM boolean/rich dependencies and capability expressions carry semantics
    beyond Pisi 1.2's single package relation.  Treating them as a package
    name would create a malformed or weaker dependency, so callers must omit
    them and retain an explicit metadata-loss flag instead.
    """
    text = str(value).strip()
    if text.startswith(("rpmlib(", "rtld(")):
        return False
    if text.startswith("("):
        return True
    if re.search(r"\s+(?:and|or|if|unless|with|without|else)\s+", text, re.IGNORECASE):
        return True
    return "(" in text or ")" in text


class RpmParser(PackageParser):
    format_name = "rpm"

    def parse(self, package: Path, workdir: Path, *, signature_keyring: Path | None = None) -> ParsedPackage:
        check_input_size(package)
        blob = package.read_bytes()
        if not blob.startswith(RPM_LEAD_MAGIC) or len(blob) < 96:
            raise UnsupportedFormatError("not a version 4 RPM package")
        signature = _read_header(blob, 96)
        main_header_offset = (signature.end + 7) & ~7
        if any(blob[signature.end:main_header_offset]):
            raise UnsupportedFormatError("RPM signature-header padding is not zero-filled")
        header = _read_header(blob, main_header_offset)
        compressed_payload = blob[header.end:]
        integrity = _verify_rpm_digests(blob, signature, header, compressed_payload)
        payload = _decompress_payload(compressed_payload, header.get("payloadcompressor", "gzip"))
        expected_uncompressed = _first_tag(header.tags, TAG["payloadsha256alt"])
        if expected_uncompressed:
            actual_uncompressed = hashlib.sha256(payload).hexdigest()
            if actual_uncompressed != str(expected_uncompressed).strip().lower():
                raise UnsupportedFormatError("RPM uncompressed payload SHA-256 verification failed")
            integrity["uncompressed-payload-sha256"] = "verified"
        expected_uncompressed_sha512 = _first_tag(header.tags, TAG["payloadsha512alt"])
        if expected_uncompressed_sha512:
            actual_uncompressed_sha512 = hashlib.sha512(payload).hexdigest()
            if actual_uncompressed_sha512 != str(expected_uncompressed_sha512).strip().lower():
                raise UnsupportedFormatError("RPM uncompressed payload SHA-512 verification failed")
            integrity["uncompressed-payload-sha512"] = "verified"
        expected_uncompressed_sha3 = _first_tag(header.tags, 5124)
        if expected_uncompressed_sha3:
            actual_uncompressed_sha3 = hashlib.sha3_256(payload).hexdigest()
            if actual_uncompressed_sha3 != str(expected_uncompressed_sha3).strip().lower():
                raise UnsupportedFormatError("RPM uncompressed payload SHA3-256 verification failed")
            integrity["uncompressed-payload-sha3-256"] = "verified"
        root = workdir / "payload"
        root.mkdir(parents=True, exist_ok=True)
        warnings: list[str] = []
        source_metadata: dict[str, dict[str, int]] = {}
        metadata_flags: list[str] = []
        if any(tag in signature.tags for tag in (259, 262, 267, 268, 278)):
            if signature_keyring:
                integrity["openpgp-signature"] = _verify_rpm_openpgp(blob, signature, header, signature_keyring)
            else:
                warnings.append("RPM OpenPGP signature is present but was not verified by EveryPisi")
                integrity["openpgp-signature"] = "present-unverified"
        if header.get("filecaps", []) not in (None, [], ""):
            metadata_flags.append("RPM file capabilities are not retained")
        trigger_tags = {
            1065, 1066, 1067, 1068, 1069, 1092, 1100, 1101, 1102,
            1171, 5005, 5006, 5027, 5063, 5064, 5065, 5066, 5067,
            5068, 5069, 5070, 5071, 5072, 5073, 5074, 5075, 5076,
            5077, 5078, 5079, 5080, 5081, 5082, 5084, 5085, 5086,
            5087, 5088, 5089,
        }
        if trigger_tags.intersection(header.tags):
            metadata_flags.append("RPM triggers are not portable to Pisi")
        for relation_kind, relation_names in (
                ("requires", _as_list(header.get("requirename", []))),
                ("conflicts", _as_list(header.get("conflictname", []))),
                ("obsoletes", _as_list(header.get("obsoletename", [])))):
            for relation_name in relation_names or []:
                if _unsupported_rpm_relation(relation_name):
                    metadata_flags.append(
                        f"rpm-{relation_kind}-not-supported:{relation_name}"
                    )
        if payload.startswith(b"07070X"):
            _read_stripped(payload, root, warnings, source_metadata, header, metadata_flags)
        else:
            _read_newc(payload, root, warnings, source_metadata, metadata_flags)
        integrity["file-digests"] = _verify_rpm_file_digests(header, root, source_metadata)
        scripts = []
        for tag_name, script_name in (("prein", "%pre"), ("postin", "%post"), ("preun", "%preun"), ("postun", "%postun")):
            body = header.get(tag_name, "")
            if body:
                scripts.append(parse_script(script_name, body.encode()))
        deps = _dependency_atoms(header.get("requirename", []), header.get("requireshflags", []), header.get("requireversion", []))
        conflict_groups = _dependency_atoms(header.get("conflictname", []), header.get("conflictflags", []), header.get("conflictversion", []), "conflict")
        obsolete_groups = _dependency_atoms(header.get("obsoletename", []), header.get("obsoleteflags", []), header.get("obsoleteversion", []))
        for group in deps:
            atom = group.alternatives[0]
            if atom.name.startswith(("rpmlib(", "/")):
                warnings.append(f"RPM capability requires mapping: {atom.name}")
        foreign_version = str(header.get("version", "0"))
        foreign_release = str(header.get("release", "1"))
        version = normalize_pisi_version(foreign_version)
        release = normalize_pisi_release(foreign_release)
        if version != foreign_version:
            warnings.append(f"RPM version normalized for Pisi: {foreign_version} -> {version}")
            metadata_flags.append("rpm-version-normalized")
        if release != foreign_release:
            warnings.append(f"RPM release normalized for Pisi: {foreign_release} -> {release}")
            metadata_flags.append("rpm-release-normalized")
        parsed = ParsedPackage(
            "rpm", package,
            header.get("name", package.stem),
            version,
            header.get("arch", "any"),
            header.get("summary", ""), header.get("description", ""),
            header.get("url", ""), header.get("license", "Unknown"), deps,
            _as_list(header.get("providename", [])), [_relation_text(group.alternatives[0]) for group in conflict_groups if group.alternatives], scripts,
            root, raw_metadata={str(key): value for key, value in header.tags.items()}, warnings=warnings,
        )
        parsed.files = scan_payload(root, source_metadata)
        parsed.payload_metadata = source_metadata
        parsed.metadata_flags = metadata_flags
        for provided in parsed.provides:
            if provided not in {parsed.name, f"{parsed.name}({parsed.architecture})"}:
                parsed.metadata_flags.append(f"foreign-provide-not-supported:{provided}")
        parsed.metadata_flags = sorted(set(parsed.metadata_flags))
        parsed.source_integrity = integrity
        parsed.release = release
        parsed.replaces = [_relation_text(group.alternatives[0]) for group in obsolete_groups if group.alternatives]
        return parsed


def _relation_text(atom) -> str:
    if atom.operator and atom.version:
        return f"{atom.name} {atom.operator} {atom.version}"
    return atom.name
