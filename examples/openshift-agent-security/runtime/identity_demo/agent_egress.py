# SPDX-License-Identifier: Apache-2.0
"""Probe direct outbound sockets from the actual sandboxed CVE process."""

from deployment_profile import active_profile


def program() -> str:
    """Require kernel permission denial, not a timeout or unverified TLS error."""
    return '''import json,socket
cases=[]
for name,host,port in [('public_ip','1.1.1.1',443),('cluster_api','kubernetes.default.svc.cluster.local',443),('direct_jira','fixture-jira.demo-core.svc.cluster.local',8080),('private_broker','mcp-gateway.demo-core.svc.cluster.local',8080)]:
 denied=False;failure=''
 try:
  with socket.create_connection((host,port),timeout=3):pass
 except PermissionError:denied=True;failure='PermissionError'
 except Exception as error:failure=type(error).__name__
 cases.append({'case':name,'kernel_permission_denied':denied,'failure_kind':failure,'passed':denied})
print(json.dumps({'passed':all(c['passed'] for c in cases),'cases':cases}))
'''.replace('demo-core.svc.cluster.local', active_profile().core_namespace + '.svc.cluster.local')
