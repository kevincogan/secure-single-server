#!/usr/bin/env python3
"""Load generator regressions without a provider or live credentials."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
loader=importlib.machinery.SourceFileLoader('perf',str(ROOT/'scripts/pricetag/perf'))
spec=importlib.util.spec_from_loader(loader.name,loader)
perf=importlib.util.module_from_spec(spec);loader.exec_module(perf)


class Load(unittest.TestCase):
    def test_multiple_streams_per_user_and_expected_throttling(self):
        class Reply:
            status=429
            def read(self,*args): return b'limited'
        class Connection:
            def __init__(self,*args,**kwargs): self.sock=None
            def request(self,*args,**kwargs): pass
            def getresponse(self): return Reply()
            def close(self): pass
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(url='https://localhost:8443',ca=Path('unused'),tokens=Path(directory),output=Path(directory)/'report.json',model='fixture',json=True,keep_alive=False,duration=None,requests=2,lanes=3,think=0,timeout=5,concurrency=[2],allow_rate_limited=True)
            with patch.object(perf,'identities',return_value=[('perf-one','test'),('perf-two','test')]),patch.object(perf.ssl,'create_default_context'),patch.object(perf.http.client,'HTTPSConnection',Connection):
                self.assertEqual(perf.run(args),0)
            phase=json.loads(args.output.read_text())['phases'][0]
            self.assertEqual(phase['attempts'],12)
            self.assertEqual(phase['in_flight_limit'],6)
            self.assertEqual(phase['statuses'],{'429':12})
            self.assertEqual(phase['successes'],0)
            self.assertEqual({s['subject'] for s in phase['samples']},{'perf-one','perf-two'})


if __name__=='__main__': unittest.main()
