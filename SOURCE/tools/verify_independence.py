#!/usr/bin/env python3
"""Reject references to any repository other than the canonical one (VERSION.json)
in source and generated public artifacts.

No code from scanned files is executed and archives are never extracted to disk.
The encrypted compatibility envelope needs a separate owner-only plaintext audit.
"""
from pathlib import Path
from urllib.parse import unquote
import argparse
import base64
import gzip
import io
import re
import subprocess
import tarfile
import zipfile
from public_files import tracked_files
from identity import canonical, foreign_reference

MAX_MEMBER = 160 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


class IndependenceError(ValueError):
    pass


class Scanner:
    def __init__(self, repository, extra_digests=()):
        self.repository = repository
        self.extra_digests = frozenset(extra_digests)
        self.objects = 0
        self.bytes = 0

    def scan(self, label, data, depth=0):
        if depth > 10 or len(data) > MAX_MEMBER:
            raise IndependenceError(f"Scan size/depth limit: {label}")
        self.objects += 1
        self.bytes += len(data)
        if self.bytes > MAX_TOTAL:
            raise IndependenceError("Total scan size limit")
        # URL decoding catches percent-encoded paths in URLs and JSON values.
        # For native/compressed binary data, inspect printable strings rather
        # than expanding millions of random bytes through the URL decoder.
        text = "\n".join(match[0].decode("ascii") for match in re.finditer(rb"[\x20-\x7e]{8,}", data)) if b"\0" in data else data.decode("latin-1")
        for _ in range(3):
            decoded = unquote(text)
            if decoded == text:
                break
            text = decoded
        text = text.replace(r"\/", "/")
        problem = foreign_reference(text, self.repository, self.extra_digests)
        if problem:
            # Print paths only: the containing line may hold a private token.
            raise IndependenceError(f"Repository identity violation ({problem}): {label}")
        if data.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
            raise IndependenceError(f"Unresolved LFS pointer: {label}")
        if data.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                unpacked = stream.read(MAX_MEMBER + 1)
            self.scan(label + "::gzip", unpacked, depth + 1)
            return
        if zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    if member.file_size > MAX_MEMBER:
                        raise IndependenceError(f"Oversize ZIP member: {label}")
                    self.scan(label + "::" + member.filename, archive.read(member), depth + 1)
            return
        # Tar headers identify their format at a fixed offset. Do not attempt
        # to parse arbitrary binary data as a historical tar variant.
        if len(data) > 262 and data[257:262] == b"ustar":
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                for member in archive.getmembers():
                    if member.isfile():
                        if member.size > MAX_MEMBER:
                            raise IndependenceError(f"Oversize tar member: {label}")
                        self.scan(label + "::" + member.name, archive.extractfile(member).read(), depth + 1)
            return
        # Inspect the generated manager, embedded core and embedded frontend/
        # backend archive instead of assuming base64 is transparent to grep.
        for marker in ("GENERIC", "CORE"):
            pattern = rb"<<'SBOX_" + marker.encode() + rb"_PAYLOAD'\r?\n([A-Za-z0-9+/=\r\n]+)\r?\nSBOX_" + marker.encode() + rb"_PAYLOAD"
            for match in re.finditer(pattern, data):
                encoded = re.sub(rb"\s", b"", match[1])
                self.scan(label + "::embedded-" + marker.lower(), base64.b64decode(encoded, validate=True), depth + 1)
        for match in re.finditer(rb"blob=base64\.b64decode\('([A-Za-z0-9+/=]+)',validate=True\)", data):
            self.scan(label + "::web-assets", base64.b64decode(match[1], validate=True), depth + 1)


def scan_tree(root, artifacts=()):
    root = root.resolve()
    scanner = Scanner(canonical(root))
    paths = set()
    try:
        index = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=root, stderr=subprocess.DEVNULL).split(b"\0")
    except (FileNotFoundError, subprocess.CalledProcessError):
        # Packaged source trees intentionally have no Git metadata. Scan the
        # same public file boundary directly so release checks stay offline.
        paths.update(tracked_files(root))
    else:
        for row in filter(None, index):
            metadata, name = row.split(b"\t", 1)
            mode, _, stage = metadata.split()
            if mode == b"160000":
                raise IndependenceError("Unresolved Git submodule")
            if stage != b"0":
                raise IndependenceError("Unmerged source entry")
            paths.add(root / name.decode())
    # Include newly authored workflows/docs before staging as well as the
    # integrated manager built by tools/build.py.
    for directory in ("docs", "examples", ".build/src"):
        paths.update(path for path in (root / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts)
    for path in sorted(paths):
        if path.is_symlink():
            raise IndependenceError("Symlink in public source")
        scanner.scan(str(path.relative_to(root)), path.read_bytes())
    for artifact in artifacts:
        path = artifact.resolve()
        candidates = sorted(path.rglob("*")) if path.is_dir() else [path]
        for candidate in candidates:
            if candidate.is_file():
                scanner.scan(candidate.name, candidate.read_bytes())
    return scanner


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--artifact", type=Path, action="append", default=[])
    args = parser.parse_args()
    try:
        scanner = scan_tree(args.root, args.artifact)
    except (IndependenceError, OSError, EOFError, ValueError) as error:
        parser.exit(1, f"FAIL independence: {error}\n")
    print(f"PASS static independence: {scanner.objects} objects, {scanner.bytes} bytes; live server acceptance remains a separate gate")


if __name__ == "__main__":
    main()
