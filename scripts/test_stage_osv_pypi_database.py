# SPDX-FileCopyrightText: 2026 sSOFTINn
# SPDX-License-Identifier: MIT
from io import BytesIO
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
import zipfile

from stage_osv_pypi_database import URL, stage


class Reply(BytesIO):
    status = 200
    headers = {'Last-Modified': 'Tue, 01 Sep 2026 00:00:00 GMT'}
    def geturl(self):
        return URL


class StageTests(unittest.TestCase):
    def payload(self, name='TEST-ONLY.json'):
        result = BytesIO()
        with zipfile.ZipFile(result, 'w') as archive:
            archive.writestr(name, json.dumps({'id': 'TEST-ONLY', 'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'synthetic'}}]}))
        return result.getvalue()

    def test_no_network_or_output_without_explicit_manual_flag(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'candidate'
            fetch = Mock()
            with self.assertRaises(ValueError):
                stage(output, False, opener=fetch)
            fetch.assert_not_called()
            self.assertFalse(output.exists())

    def test_valid_download_stays_pending_and_cannot_overwrite(self):
        payload = self.payload()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'candidate'
            fetch = Mock(return_value=Reply(payload))
            result = stage(output, True, hashlib.sha256(payload).hexdigest(), fetch)
            self.assertEqual(fetch.call_args.args[0].full_url, URL)
            self.assertIsNone(fetch.call_args.args[0].data)
            self.assertEqual(result['status'], 'PENDING_APPROVAL')
            self.assertEqual(result['activation'], 'not_performed')
            with self.assertRaises(FileExistsError):
                stage(output, True, opener=fetch)

    def test_bad_hash_or_archive_never_produces_candidate_manifest(self):
        for payload, expected in ((self.payload(), '0' * 64), (self.payload('../escape.json'), '')):
            with tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / 'candidate'
                with self.assertRaises(ValueError):
                    stage(output, True, expected, Mock(return_value=Reply(payload)))
                self.assertFalse((output / 'candidate.json').exists())


if __name__ == '__main__':
    unittest.main()
