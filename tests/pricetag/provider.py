#!/usr/bin/env python3
"""The common native-API fixture with vLLM's no-upstream-credential contract."""
import os
import sys
import threading

sys.path.insert(0, '/fixtures')
from provider import Provider

managed = os.environ.get('MOCK_MANAGEMENT') == '1'
fixture = (Provider(host='0.0.0.0', local=False, openai_authorization='Bearer synthetic-anthropic',
                    declared_tools_only=True, request_backlog=512, record_limit=1000)
           if managed else Provider(host='0.0.0.0', local=True))
if 'MOCK_STREAM_DELAY' in os.environ:
    fixture.mode = 'delayed'
    fixture.delay = float(os.environ['MOCK_STREAM_DELAY'])
fixture.start()
threading.Event().wait()
