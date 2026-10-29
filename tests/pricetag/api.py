#!/usr/bin/env python3
import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
loader=importlib.machinery.SourceFileLoader('api',str(ROOT/'scripts/pricetag/api'))
spec=importlib.util.spec_from_loader(loader.name,loader);api=importlib.util.module_from_spec(spec);loader.exec_module(api)

class Contracts(unittest.TestCase):
 def test_rejects_credential_redirect_destinations(self):
  for origin,path in [('http://example.test','/me/keys'),('https://user:password@example.test','/me/keys'),('https://example.test','//other.test/me/keys'),('https://example.test','/api/v1/admin/../events'),('https://example.test','/api/v1/events')]:
   with self.assertRaises(ValueError):api.endpoint(origin,path)
 def test_catalog_query_is_narrowly_allowed(self):
  self.assertEqual(api.endpoint('https://example.test','/api/v1/pricing?used=0')[1],'/api/v1/pricing?used=0')
  for route in ['/api/v1/pricing?used=0&other=1','/me/keys?used=0','/api/v1/pricing?token=secret']:
   with self.assertRaises(ValueError):api.endpoint('https://example.test',route)
 def test_requires_private_owned_input(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'fixture';path.write_text('fixture');path.chmod(0o644)
   with self.assertRaises(ValueError):api.private(path)
   path.chmod(0o600);self.assertEqual(api.private(path),'fixture')
   link=Path(directory)/'link';link.symlink_to(path)
   with self.assertRaises(OSError):api.private(link)

if __name__=='__main__':unittest.main()
