#!/usr/bin/env python3
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[2]
loader=importlib.machinery.SourceFileLoader('capacity_export',str(ROOT/'scripts/pricetag/export-capacity'))
spec=importlib.util.spec_from_loader(loader.name,loader);exporter=importlib.util.module_from_spec(spec);loader.exec_module(exporter)

class Export(unittest.TestCase):
 def test_exports_only_fixed_fields(self):
  row={'monotonic_seconds':1,'cpu_ticks':[1]*10,'memory':{k:1 for k in exporter.MEMORY},'disk_available_bytes':1,'disk_available_percent':50,'load_average':[1,2,3],
       'containers':[{'name':'pricetag-gateway','cpu_time':'1.2s','mem_usage':'1MB / 1GB','credential':'MUST_NOT_EXPORT'}],
       'postgres':{'database_bytes':1,'wal_directory_bytes':1,'usage_events':1,'connection_string':'MUST_NOT_EXPORT'},'environment':'MUST_NOT_EXPORT'}
  result=json.dumps(exporter.observation(row))
  self.assertNotIn('MUST_NOT_EXPORT',result)
  row['containers'][0]['cpu_time']='secret-value'
  with self.assertRaises(ValueError):exporter.observation(row)
 def test_rejects_nonfinite_and_boolean_measurements(self):
  for value in [float('nan'),float('inf'),True,-1,'token']:
   with self.assertRaises(ValueError):exporter.number(value)

if __name__=='__main__':unittest.main()
