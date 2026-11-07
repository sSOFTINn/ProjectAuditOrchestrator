"""PAO-owned, offline preparation inside a pinned Docker Desktop VM only.

Inputs are the setup download cache and its hash lock, never an audit target.
The caller fixes the mode, mounts, user, resource limits and network isolation.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import venv

ROOT = Path('/pao/state')
INPUT = Path('/inputs')
LOCK = json.loads(Path('/recipe/inputs.json').read_text())


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def artifact(name):
    row = LOCK[name]
    path = INPUT / row['filename']
    if path.parent != INPUT or not path.is_file() or path.is_symlink():
        raise ValueError('invalid prepared input')
    if digest(path) != row['sha256']:
        raise ValueError('prepared input hash mismatch')
    return path


def unpack(path, destination):
    with tarfile.open(path, 'r:gz') as archive:
        members = archive.getmembers()
        seen, size = set(), 0
        if len(members) > 100000:
            raise ValueError('archive member limit')
        for member in members:
            p = Path(member.name)
            key = member.name.lower().rstrip('/')
            if (p.is_absolute() or '..' in p.parts or '\\' in member.name
                    or ':' in member.name or key in seen
                    or not (member.isdir() or member.isfile())):
                raise ValueError('unsafe archive member')
            seen.add(key)
            size += member.size
            if member.size > 4 * 1024**3 or size > 4 * 1024**3:
                raise ValueError('archive expanded byte limit')
        archive.extractall(destination, members=members, filter='data')


def command(args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True, timeout=1800,
                   env={**os.environ, 'PIP_NO_INDEX': '1',
                        'PIP_DISABLE_PIP_VERSION_CHECK': '1',
                        'PYTHONDONTWRITEBYTECODE': '1', 'HOME': '/tmp'})


def python_state(mode):
    envdir = ROOT / 'venv'
    venv.EnvBuilder(with_pip=True, symlinks=False).create(envdir)
    python = str(envdir / 'bin/python')
    if mode == 'scancode':
        unpack(artifact('scancode'), ROOT / 'distribution')
        distribution = ROOT / 'distribution/scancode-toolkit-v32.5.0'
        wheels = list(distribution.glob('scancode_toolkit-*.whl'))
        if len(wheels) != 1:
            raise ValueError('expected exactly one pinned ScanCode wheel')
        command([python, '-m', 'pip', 'install', '--no-index', '--no-compile',
                 '--find-links', str(distribution / 'thirdparty'), str(wheels[0])])
        # 32.5.0 exposes reindexing as a separate console entry point. Prime
        # only the tool-owned index in this state capsule, never a user project.
        command([str(envdir / 'bin/scancode-reindex-licenses')])
        command([python, '-c',
                 'from pathlib import Path; '
                 'from scancode_config import licensedcode_cache_dir; '
                 'from licensedcode.cache import get_cache; '
                 'cache = Path(licensedcode_cache_dir) / "license_index" / "index_cache"; '
                 'assert cache.resolve().is_relative_to(Path("/pao/state")); '
                 'assert cache.is_file() and cache.stat().st_size > 0; '
                 'assert get_cache().db, "license cache readback is empty"'])
    else:
        wheels = [str(artifact(name)) for name, row in LOCK.items()
                  if row.get('purpose') == 'reuse-dependency']
        command([python, '-m', 'pip', 'install', '--no-index', '--no-deps', '--no-compile', *wheels])
        command([python, '-m', 'pip', 'install', '--no-index', '--no-deps',
                 '--no-build-isolation', '--no-compile', str(artifact('reuse'))])
        command([python, '-m', 'reuse', '--version'])
    # CPython creates this optional alias even for --copies. It is unnecessary
    # for the admitted interpreter and cannot enter a link-free state capsule.
    alias = envdir / 'lib64'
    if alias.is_symlink() and alias.resolve() == (envdir / 'lib').resolve():
        alias.unlink()
    for entry in ROOT.rglob('*'):
        if entry.is_symlink():
            raise ValueError('state contains an unexpected symlink')
        if entry.is_dir():
            entry.chmod(0o755)
        elif entry.is_file():
            entry.chmod(0o755 if entry.stat().st_mode & 0o111 else 0o644)


def main():
    if os.geteuid() == 0 or len(sys.argv) != 2 or sys.argv[1] not in ('scancode', 'reuse', 'opengrep', 'grype'):
        raise SystemExit('non-root fixed preparation mode required')
    if not ROOT.is_dir() or ROOT.is_symlink() or list(ROOT.iterdir()):
        raise SystemExit('fresh private state mount required')
    if sys.argv[1] == 'grype':
        subprocess.run(['/grype', 'db', 'import', '/database-source/vulnerability.db'],
                       check=True, timeout=1800, env={**os.environ,
                           'GRYPE_DB_CACHE_DIR': str(ROOT), 'GRYPE_DB_AUTO_UPDATE': 'false',
                           'GRYPE_CHECK_FOR_APP_UPDATE': 'false'})
    elif sys.argv[1] == 'opengrep':
        Path('/tmp/fixture.py').write_text('value = 1\n')
        Path('/tmp/rules.yml').write_text('rules:\n  - id: setup-synthetic\n    languages: [python]\n    message: synthetic only\n    severity: INFO\n    pattern: value = 1\n')
        # OpenGrep 1.29.0 has no --metrics option. These scan arguments are
        # declared by its pinned Scan_CLI.ml; the report path is synthetic.
        subprocess.run([str(artifact('opengrep')), 'scan', '--config', '/tmp/rules.yml',
                        '--disable-version-check', '--json', '--json-output',
                        '/tmp/results.json', '/tmp/fixture.py'],
                       check=True, timeout=120, env={**os.environ,
                           'HOME': str(ROOT), 'TMPDIR': str(ROOT),
                           'XDG_CACHE_HOME': str(ROOT), 'SEMGREP_LOG_FILE': '/tmp/setup.log'})
        (ROOT / 'preparation.txt').write_text('PAO synthetic-only OpenGrep preparation\n')
    else:
        python_state(sys.argv[1])


if __name__ == '__main__':
    main()
