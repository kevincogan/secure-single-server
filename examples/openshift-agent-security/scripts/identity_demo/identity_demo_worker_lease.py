# SPDX-License-Identifier: Apache-2.0
"""Fail-closed process ownership using an installer-created Kubernetes Lease.

Never create a Lease or retry an uncertain update. A fresh API read can confirm
an earlier update by this process; it cannot authorize replay of a demo mutation.
The driver's durable run/preparation ownership remains a second independent gate.
"""
from __future__ import annotations

from datetime import datetime, timezone
import atexit
import json
import os
from pathlib import Path
import threading
import time
from uuid import uuid4

import httpx


_process_lease = None


class LeaseUnavailable(RuntimeError):
    pass


def utc_seconds(value: str) -> float:
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


class WorkerLease:
    duration = 45
    freshness = 12

    def __init__(self, args, role, *, client=None, monotonic=time.monotonic, now=time.time):
        from deployment_profile import active_profile
        self.profile = active_profile()
        if role not in ('coordinator', 'preparer'):
            raise ValueError('Exact runtime role required')
        if (not args.service_account_token_file or args.service_account_namespace != self.profile.core_namespace
                or args.service_account_name != 'fixture-console-' + role or not args.pod_uid):
            raise ValueError('Pod-bound role authentication required for worker lease')
        self.token = Path(args.service_account_token_file)
        self.name = 'fixture-console-' + role
        self.path = '/apis/coordination.k8s.io/v1/namespaces/' + self.profile.core_namespace + '/leases/' + self.name
        self.holder = args.pod_uid + '/' + uuid4().hex
        self.client = client or httpx.Client(base_url=self.profile.expected_server,
            verify=os.environ['IDENTITY_DEMO_KUBERNETES_CA'], timeout=5,
            follow_redirects=False, trust_env=False)
        self.monotonic, self.now = monotonic, now
        self.last_confirmed = None
        self.uid = None
        self.lost = threading.Event()
        self.stop = threading.Event()
        self.thread = None
        self.lock = threading.Lock()
        self.health_file = Path(args.output_dir).parent/'worker-lease-health.json' if getattr(args, 'output_dir', None) else None

    def request(self, method, body=None):
        # Reopen tokenFile on every request: kubelet replaces it atomically.
        token = self.token.read_text().strip()
        if not 16 <= len(token) <= 16384 or any(c.isspace() for c in token):
            raise LeaseUnavailable('Projected lease credential unavailable')
        response = self.client.request(method, self.path,
            headers={'Authorization': 'Bearer ' + token}, json=body)
        if response.status_code != 200 or len(response.content) > 32768:
            raise LeaseUnavailable('Lease API rejected ownership operation')
        return response.json()

    def renew(self, *, acquire=False):
        with self.lock:
            if self.lost.is_set():
                raise LeaseUnavailable('Worker ownership was lost')
            obj = self.request('GET')
            meta, spec = obj['metadata'], obj.get('spec', {})
            if (meta.get('namespace') != self.profile.core_namespace or meta.get('name') != self.name
                    or not meta.get('uid') or not meta.get('resourceVersion')
                    or any(meta.get('labels', {}).get(k) != v for k, v in self.profile.labels.items())
                    or (self.uid is not None and meta['uid'] != self.uid)):
                self.lost.set()
                raise LeaseUnavailable('Installer-owned lease identity changed')
            holder = spec.get('holderIdentity')
            if holder and holder != self.holder:
                expiry = utc_seconds(spec['renewTime']) + spec['leaseDurationSeconds']
                if not acquire or expiry >= self.now():
                    self.lost.set()
                    raise LeaseUnavailable('Another runtime process owns the lease')
            elif not acquire and holder != self.holder:
                self.lost.set()
                raise LeaseUnavailable('Worker lease no longer belongs to this process')
            stamp = datetime.fromtimestamp(self.now(), timezone.utc).isoformat().replace('+00:00', 'Z')
            obj['spec'] = {**spec, 'holderIdentity': self.holder,
                           'leaseDurationSeconds': self.duration, 'renewTime': stamp}
            if holder != self.holder:
                obj['spec']['acquireTime'] = stamp
                obj['spec']['leaseTransitions'] = spec.get('leaseTransitions', 0) + 1
            updated = self.request('PUT', obj)
            if updated.get('spec', {}).get('holderIdentity') != self.holder or updated['metadata']['uid'] != meta['uid']:
                self.lost.set()
                raise LeaseUnavailable('Lease update was not confirmed')
            self.uid = meta['uid']
            self.last_confirmed = self.monotonic()
            if self.health_file:
                temporary = self.health_file.with_name('.worker-lease-health-'+uuid4().hex)
                with os.fdopen(os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'w') as stream:
                    json.dump({'at': self.now(), 'holder': self.holder, 'lease_uid': self.uid}, stream)
                temporary.replace(self.health_file)

    def assert_current(self):
        if (self.lost.is_set() or self.last_confirmed is None
                or self.monotonic() - self.last_confirmed >= self.freshness):
            raise LeaseUnavailable('Fresh worker ownership could not be proved')

    def run(self):
        while not self.stop.wait(3):
            try:
                self.renew()
            except Exception:
                # Never reacquire after a competing holder. API outages fail
                # requests closed after freshness, well before lease expiry.
                if self.lost.is_set():
                    return

    def start(self):
        self.renew(acquire=True)
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=6)
        self.client.close()
        # Do not clear/release ownership ahead of in-flight requests. A new
        # process waits for expiry and must pass driver's durable recovery gate.


def install(args, role):
    global _process_lease
    mode = os.environ.get('IDENTITY_DEMO_RUNTIME', 'local')
    if mode == 'local':
        return None
    if mode != 'cluster' or _process_lease is not None:
        raise ValueError('One explicit runtime lease per process required')
    _process_lease = WorkerLease(args, role).start()
    atexit.register(_process_lease.close)
    return _process_lease


def assert_current():
    if os.environ.get('IDENTITY_DEMO_RUNTIME', 'local') == 'cluster':
        if _process_lease is None:
            raise LeaseUnavailable('Cluster runtime has no process lease')
        _process_lease.assert_current()
