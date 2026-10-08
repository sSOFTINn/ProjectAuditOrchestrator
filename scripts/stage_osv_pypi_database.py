# SPDX-FileCopyrightText: 2026 sSOFTINn
# SPDX-License-Identifier: MIT
"""Owner-started public database download; never scans a project or approves data."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import zipfile

URL = 'https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip'
LIMIT = 256 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('database redirects are not permitted')


def local_parent(path: Path) -> Path:
    path = path.absolute()
    if str(path).startswith(('\\\\', '//')):
        raise ValueError('local fixed drive required')
    if os.name == 'nt':
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(path.anchor) != 3:
            raise ValueError('local fixed drive required')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('redirected output is forbidden')
    return path


def validate_archive(path: Path) -> int:
    count = 0
    total = 0
    pypi = False
    with zipfile.ZipFile(path) as archive:
        names = set()
        for info in archive.infolist():
            name = PurePosixPath(info.filename)
            if (info.is_dir() or name.is_absolute() or '..' in name.parts or '\\' in info.filename
                    or ':' in info.filename or name.suffix != '.json' or info.filename in names
                    or stat.S_ISLNK(info.external_attr >> 16)):
                raise ValueError('unexpected or unsafe database entry')
            names.add(info.filename)
            total += info.file_size
            count += 1
            if info.file_size > 2 * 1024 * 1024 or total > 512 * 1024 * 1024 or count > 100000:
                raise ValueError('database exceeds validation budget')
            record = json.loads(archive.read(info))
            if not isinstance(record, dict) or not isinstance(record.get('id'), str):
                raise ValueError('invalid OSV record')
            for affected in record.get('affected', []):
                if affected.get('package', {}).get('ecosystem') == 'PyPI':
                    pypi = True
        if not count or not pypi:
            raise ValueError('database has no PyPI coverage')
    return count


def stage(output: Path, manual: bool, expected_hash: str = '', opener=None) -> dict:
    if not manual:
        raise ValueError('explicit --manual invocation required; nothing downloaded')
    if expected_hash and not re.fullmatch('[a-f0-9]{64}', expected_hash):
        raise ValueError('invalid expected SHA-256')
    parent = local_parent(output.absolute().parent)
    output = parent / output.name
    output.mkdir()  # refuses existing files/directories; never overwrites candidates
    request = Request(URL, headers={'User-Agent': 'PAO-database-preparation/1'})
    fetch = opener or build_opener(ProxyHandler({}), NoRedirect()).open
    archive_path = output / 'PyPI-all.zip'
    h = hashlib.sha256()
    size = 0
    now = datetime.now(timezone.utc)
    with fetch(request, timeout=60) as response:
        if response.status != 200 or response.geturl() != URL:
            raise ValueError('unexpected database response')
        updated = parsedate_to_datetime(response.headers['Last-Modified'])
        if updated.tzinfo is None or updated > now:
            raise ValueError('missing or invalid upstream timestamp')
        with archive_path.open('xb') as target:
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > LIMIT:
                    raise ValueError('database exceeds download budget')
                h.update(chunk)
                target.write(chunk)
    checksum = h.hexdigest()
    if expected_hash and checksum != expected_hash:
        raise ValueError('SHA-256 mismatch; candidate is unusable')
    with archive_path.open('rb') as readback:
        if hashlib.file_digest(readback, 'sha256').hexdigest() != checksum:
            raise ValueError('download readback mismatch')
    records = validate_archive(archive_path)
    metadata = {'schema': 'pao-database-candidate/v1', 'ecosystem': 'PyPI', 'source': URL,
                'status': 'PENDING_APPROVAL', 'sha256': checksum, 'size': size,
                'downloaded_at': now.isoformat(), 'updated_at': updated.isoformat(),
                'records': records, 'publisher_hash_compared': bool(expected_hash),
                'approval_owner_required': 'sSOFTINn', 'activation': 'not_performed'}
    with (output / 'candidate.json').open('x', encoding='utf-8') as manifest:
        json.dump(metadata, manifest, indent=2)
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--manual', action='store_true')
    parser.add_argument('--expected-sha256', default='')
    args = parser.parse_args()
    try:
        print(json.dumps(stage(args.output, args.manual, args.expected_sha256), indent=2))
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile):
        parser.exit(1, 'BLOCKED: candidate not approved; any partial download remains quarantined\n')
