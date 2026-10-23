# SPDX-License-Identifier: Apache-2.0
"""Installer-owned SPIRE policies; runtime identities cannot write registrations.

The existing SPIRE controller supplies the exact Pod UID and attested node parent.
These policies add the installation, service account, container and image bounds.
They are installed by the administrator, never the coordinator or preparer.
"""
from __future__ import annotations

import os
import time

from deployment_profile import active_profile
from deployment_artifacts import IMAGE_REFERENCE, configured_native_image

CLASS = "zero-trust-workload-identity-manager-spire"


def enabled() -> bool:
    mode = os.environ.get("IDENTITY_DEMO_REGISTRATION_MODE", "static")
    if mode not in {"static", "controller"}:
        raise ValueError("Explicit static/controller registration mode required")
    return mode == "controller"


def policy(profile, role: str, image: str) -> dict:
    if role not in {"triage", "reader"} or not IMAGE_REFERENCE.fullmatch(image):
        raise ValueError("Exact role and pinned supervisor image required")
    namespace = profile.namespace_for(role)
    # A wrong/missing label, namespace, SA, image or Pod-name mapping renders an
    # empty (invalid) SPIFFE ID. It can never fall back to a less specific ID.
    conditions = [
        '(eq .PodMeta.Namespace "' + namespace + '")',
        '(eq .PodSpec.ServiceAccountName "fixture-openshell-sandbox")',
        '(eq (len .PodSpec.Containers) 1)',
        '(eq (index .PodSpec.Containers 0).Name "supervisor")',
        '(eq (index .PodSpec.Containers 0).Image "' + image + '")',
        '(eq .PodMeta.Name (printf "os-supervisor-%s" (index .PodMeta.Labels "openshell.ai/sandbox-id")))',
        '(eq (index .PodMeta.Labels "openshell.ai/sandbox-id") (index .PodMeta.Labels "openshell.ai/boundary-pair"))',
    ]
    template = '{{ if and ' + ' '.join(conditions) + ' }}spiffe://' + profile.trust_domain
    template += '/openshell/sandbox/{{ index .PodMeta.Labels "openshell.ai/sandbox-id" }}{{ end }}'
    return {"apiVersion": "spire.spiffe.io/v1alpha1", "kind": "ClusterSPIFFEID",
        "metadata": {"name": "identity-demo-" + profile.installation_id + "-" + role + "-native",
                     "labels": dict(profile.labels)},
        "spec": {"className": CLASS, "spiffeIDTemplate": template,
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
            "podSelector": {"matchLabels": {
                "openshell.ai/gateway-id": profile.gateway_id,
                "openshell.ai/managed-by": "openshell",
                "openshell.ai/boundary-role": "supervisor"}},
            "workloadSelectorTemplates": ["k8s:ns:" + namespace,
                "k8s:sa:fixture-openshell-sandbox", "k8s:container-name:supervisor",
                "k8s:container-image:" + image],
            "ttl": "2m", "jwtTtl": "2m", "admin": False, "downstream": False}}


def gateway_policy(profile, image: str) -> dict:
    if not IMAGE_REFERENCE.fullmatch(image):
        raise ValueError('Exact pinned gateway image required')
    namespace = profile.core_namespace
    conditions = ['(eq .PodMeta.Namespace "'+namespace+'")',
        '(eq .PodMeta.Name "fixture-openshell-0")',
        '(eq .PodSpec.ServiceAccountName "fixture-openshell")',
        '(eq (len .PodSpec.Containers) 1)',
        '(eq (index .PodSpec.Containers 0).Name "openshell-gateway")',
        '(eq (index .PodSpec.Containers 0).Image "'+image+'")']
    return {'apiVersion': 'spire.spiffe.io/v1alpha1', 'kind': 'ClusterSPIFFEID',
        'metadata': {'name': 'identity-demo-'+profile.installation_id+'-gateway-native',
                     'labels': dict(profile.labels)},
        'spec': {'className': CLASS,
            'spiffeIDTemplate': '{{ if and '+' '.join(conditions)+' }}spiffe://'+profile.trust_domain+'/openshell/gateway/'+profile.gateway_id+'{{ end }}',
            'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': namespace}},
            'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'openshell',
                'app.kubernetes.io/instance': 'fixture-openshell'}},
            'workloadSelectorTemplates': ['k8s:ns:'+namespace, 'k8s:sa:fixture-openshell',
                'k8s:container-name:openshell-gateway', 'k8s:container-image:'+image],
            'ttl': '2m', 'jwtTtl': '2m', 'admin': False, 'downstream': False}}


def verify(context, read, *, require_status: bool = True) -> dict:
    """Check the immutable installer policy and the real supervisor association.

    This validates controller input/readiness, not possession of an SVID. The
    existing native exchange and protected-read gate must still prove issuance.
    """
    profile = active_profile()
    image = configured_native_image("openshell_supervisor")
    if not image:
        raise ValueError("Controller identities require a target-bound artifact lock")
    desired = policy(profile, context.role, image)
    return verify_policy(desired, read, require_status=require_status)


def verify_policy(desired, read, *, require_status=True):
    profile = active_profile()
    actual = read("clusterspiffeids.spire.spiffe.io", desired["metadata"]["name"], None)
    if (actual.get("spec") != desired["spec"] or not actual["metadata"].get("uid")
            or any(actual["metadata"].get("labels", {}).get(k) != v
                   for k, v in profile.labels.items())):
        raise ValueError("Installer-owned exact controller policy required")
    if require_status:
        stats = actual.get("status", {}).get("stats", {})
        if (stats.get("namespacesSelected") != 1
                or stats.get("podsSelected", 0) < 1
                or stats.get('entriesToSet') != stats.get('podsSelected')
                or any(stats.get(k, 0) for k in
                       ("podEntryRenderFailures", "entryFailures", "entriesMasked"))):
            raise ValueError("Controller registration reconciliation is not ready")
    return actual


def verify_gateway(read):
    profile = active_profile()
    image = configured_native_image('openshell_gateway')
    if not image:
        raise ValueError('Target-bound gateway artifact required')
    result = verify_policy(gateway_policy(profile, image), read)
    pod = read('pod', 'fixture-openshell-0', profile.core_namespace)
    statefulset = read('statefulset', 'fixture-openshell', profile.core_namespace)
    expected = statefulset['metadata']['uid']
    containers = pod['spec'].get('containers', [])
    statuses = pod.get('status', {}).get('containerStatuses', [])
    if (pod['spec'].get('serviceAccountName') != 'fixture-openshell'
            or len(containers) != 1 or containers[0]['name'] != 'openshell-gateway'
            or containers[0]['image'] != image or len(statuses) != 1
            or statuses[0].get('imageID') != image or not statuses[0].get('ready')
            or not any(v.get('uid') == expected and v.get('kind') == 'StatefulSet'
                       for v in pod['metadata'].get('ownerReferences', []))):
        raise ValueError('Exact ready gateway Pod/controller association required')
    return result


def wait_ready(context, read, timeout: int = 60) -> dict:
    end = time.monotonic() + timeout
    while True:
        try:
            return verify(context, read)
        except ValueError:
            if time.monotonic() >= end:
                raise
            time.sleep(1)
