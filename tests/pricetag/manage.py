#!/usr/bin/env python3
"""Private management client never prints responses or overwrites output files."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
loader = importlib.machinery.SourceFileLoader('manage', str(ROOT / 'scripts/pricetag/manage'))
spec = importlib.util.spec_from_loader(loader.name, loader)
manage = importlib.util.module_from_spec(spec)
loader.exec_module(manage)


class Client(unittest.TestCase):
    def test_response_is_private_and_not_printed(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'response.json'
            output = io.StringIO()
            with patch.object(sys, 'argv', ['manage','GET','users','--output',str(target)]), \
                    patch.object(manage.os,'geteuid',return_value=0), \
                    patch.object(manage,'request',return_value={'key':'synthetic-secret'}) as request, \
                    contextlib.redirect_stdout(output):
                manage.main()
            request.assert_called_once_with('GET','users',None)
            self.assertEqual(target.stat().st_mode & 0o777,0o600)
            self.assertEqual(json.loads(target.read_text()),{'key':'synthetic-secret'})
            self.assertNotIn('synthetic-secret',output.getvalue())

    def test_existing_output_prevents_api_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'existing';target.write_text('preserve')
            with patch.object(sys,'argv',['manage','GET','users','--output',str(target)]), \
                    patch.object(manage.os,'geteuid',return_value=0),patch.object(manage,'request') as request:
                with self.assertRaises(FileExistsError):manage.main()
            request.assert_not_called();self.assertEqual(target.read_text(),'preserve')

    def test_unprotected_input_prevents_api_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'input';source.write_text('{}');source.chmod(0o644)
            target=Path(directory)/'output'
            with patch.object(sys,'argv',['manage','PUT','users','--input',str(source),'--output',str(target)]), \
                    patch.object(manage.os,'geteuid',return_value=0),patch.object(manage,'request') as request:
                with self.assertRaisesRegex(ValueError,'private'):manage.main()
            request.assert_not_called();self.assertFalse(target.exists())

    def test_api_failure_retains_response_file_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'response'
            with patch.object(sys,'argv',['manage','GET','users','--output',str(target)]), \
                    patch.object(manage.os,'geteuid',return_value=0), \
                    patch.object(manage,'request',side_effect=ValueError('synthetic-secret')) as request:
                with self.assertRaisesRegex(ValueError,'inspect server state') as error:manage.main()
            self.assertNotIn('synthetic-secret',str(error.exception));self.assertTrue(target.exists())
            self.assertEqual(request.call_count,1)


if __name__ == '__main__':unittest.main()
