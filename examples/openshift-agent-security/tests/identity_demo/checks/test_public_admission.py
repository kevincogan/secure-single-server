# SPDX-License-Identifier: Apache-2.0
"""Flood admission does not consume sessions, request bodies or private capacity."""
import asyncio

import httpx
from starlette.responses import JSONResponse

from identity_demo_admission import PublicAdmission


def test_budget_recovers_and_ignores_spoofed_forwarding_headers():
    async def exercise():
        calls=[]
        async def app(scope, receive, send):
            calls.append(scope['path'])
            await JSONResponse({'ok':True})(scope, receive, send)
        clock={'now':0}
        guarded=PublicAdmission(app, clock=lambda:clock['now'], login_burst=2, login_rate=1)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=guarded),base_url='https://demo.example') as client:
            assert (await client.get('/login')).status_code==200
            assert (await client.get('/callback')).status_code==200
            for fake in ('first', 'second'):
                response=await client.get('/login',headers={'x-forwarded-for':fake})
                assert response.status_code==429 and response.headers['retry-after']=='2'
            assert (await client.get('/healthz')).status_code==200
            assert (await client.get('/runs')).status_code==200
            clock['now']=1
            assert (await client.get('/login')).status_code==200
        assert calls.count('/login')==2 and calls.count('/callback')==1
    asyncio.run(exercise())


def test_busy_request_is_rejected_before_body_or_application_and_slot_is_released():
    async def exercise():
        entered,finish=asyncio.Event(),asyncio.Event()
        async def app(scope, receive, send):
            if scope['path']!='/healthz':
                entered.set()
                await finish.wait()
            await JSONResponse({'ok':True})(scope,receive,send)
        guarded=PublicAdmission(app,maximum=1)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=guarded),base_url='https://demo.example') as client:
            first=asyncio.create_task(client.get('/runs'))
            await entered.wait()
            assert (await client.get('/runs')).status_code==429
            assert (await client.get('/healthz')).status_code==200
            finish.set()
            assert (await first).status_code==200
            assert (await client.get('/runs')).status_code==200
        assert guarded.active==0
    asyncio.run(exercise())
