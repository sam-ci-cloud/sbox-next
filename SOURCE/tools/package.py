#!/usr/bin/env python3
"""Deterministic public source archive from the reviewed source tree."""
from pathlib import Path, PurePosixPath
import argparse, hashlib, json, stat, zipfile
from public_files import is_public, tracked_files
ROOT = Path(__file__).resolve().parents[1]
def sha(data):
    return hashlib.sha256(data).hexdigest()
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    files = {}
    for path in tracked_files(ROOT):
        name = path.relative_to(ROOT).as_posix()
        if not is_public(name) or name == 'SHA256SUMS':continue
        path = PurePosixPath(name)
        assert not path.is_absolute() and '..' not in path.parts
        assert not {'.git', '.build', '.cache', 'private', 'evidence', 'dist', '__pycache__'}.intersection(path.parts)
        assert '.private' not in name and not (ROOT / name).is_symlink()
        mode = 0o755 if (ROOT / name).stat().st_mode & 0o111 else 0o644
        files[name] = ((ROOT / name).read_bytes(), mode)
    assert {'install.sh', 'LICENSE', 'src/manager.sh', 'core-source/sing-box/go.sum'} <= files.keys(), 'Stage reviewed project files before packaging'
    version = json.loads(files['assets/release.json'][0])['version']
    prefix = 'sbox-' + version
    sums = ''.join(sha(data) + '  ' + name + '\n' for name, (data, _) in sorted(files.items())).encode()
    files['SHA256SUMS'] = (sums, 0o644)
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output / (prefix + '-source.zip')
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, (data, mode) in sorted(files.items()):
            member = zipfile.ZipInfo(prefix + '/' + name, (2026, 10, 28, 0, 0, 0))
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with zipfile.ZipFile(output) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(files)
        for member in archive.infolist():
            relative = member.filename.removeprefix(prefix + '/')
            assert relative in files and '..' not in PurePosixPath(relative).parts
            data, mode = files[relative]
            assert archive.read(member) == data and ((member.external_attr >> 16) & 0o777) == mode
    (args.output / (output.name + '.sha256')).write_text(sha(output.read_bytes()) + '  ' + output.name + '\n')
    (args.output / 'SHA256SUMS').write_bytes(sums)
    print(json.dumps({'archive': str(output), 'sha256': sha(output.read_bytes()), 'files': len(files), 'status': 'PASS'}, indent=2))
if __name__ == '__main__':
    main()
