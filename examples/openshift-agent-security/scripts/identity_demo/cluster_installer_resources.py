# SPDX-License-Identifier: Apache-2.0
"""Scoped build-stage authority; no global writes, signing keys or SPIRE exec.

Administrator-created admission binds the installer principal to its owned build
namespace and tokenless child Jobs. Application authority is a separate handoff.
"""

import json
from cluster_console_resources import resource
from deployment_artifacts import IMAGE_REFERENCE
from deployment_profile import DeploymentProfile
from cluster_installer_session import configuration


def namespace_objects(profile):
    """Reuse the application namespace templates without generating credentials."""
    from source_render import read_json, TOKENS
    import identity_demo_setup as setup

    template = read_json(setup.ROOT / "infra/identity-demo/templates/application.json")
    values = profile.to_dict()
    objects = []
    for obj in template["objects"]:
        if obj["kind"] != "Namespace":
            continue

        def replace(match):
            if match.group(1) not in values:
                raise ValueError("Namespace template has an unsupported input")
            return values[match.group(1)]

        rendered = json.loads(TOKENS.sub(replace, json.dumps(obj)))
        setup.owned(rendered, profile)
        objects.append(rendered)
    if {o["metadata"]["name"] for o in objects} != set(profile.application_namespaces):
        raise ValueError("Exact three namespace templates required")
    return objects


def installer_pull_grants(profile, image, builder_image=None):
    namespace = profile.core_namespace + "-build"
    prefix = "image-registry.openshift-image-registry.svc:5000/" + namespace + "/"
    if not IMAGE_REFERENCE.fullmatch(image) or not image.startswith(prefix):
        raise ValueError("Owned immutable installer image required")
    repository = image[len(prefix) :].split("@")[0]
    if "/" in repository or not repository.startswith("fixture-agent-installer-"):
        raise ValueError("Exact installer image repository required")
    repositories = [repository]
    accounts = ["default", "fixture-installer-build-operator", "fixture-installer"]
    if builder_image and builder_image.startswith(
        prefix + "fixture-native-builder-base@"
    ):
        repositories.append("fixture-native-builder-base")
        accounts.append("builder")
    name = "identity-demo-" + profile.installation_id + "-installer-pull"
    return [
        resource(
            profile,
            "rbac.authorization.k8s.io/v1",
            "Role",
            name,
            namespace,
            rules=[
                {
                    "apiGroups": ["image.openshift.io"],
                    "resources": ["imagestreams/layers"],
                    "resourceNames": repositories,
                    "verbs": ["get"],
                }
            ],
        ),
        resource(
            profile,
            "rbac.authorization.k8s.io/v1",
            "RoleBinding",
            name,
            namespace,
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": name,
            },
            subjects=[
                {
                    "kind": "ServiceAccount",
                    "name": sa,
                    "namespace": profile.core_namespace,
                }
                for sa in accounts
            ],
        ),
    ]


def boundary(profile):
    principal = (
        "system:serviceaccount:"
        + profile.core_namespace
        + ":fixture-installer-build-operator"
    )
    name = "identity-demo-" + profile.installation_id + "-installer-build"
    regex = (
        "^image-registry[.]openshift-image-registry[.]svc:5000/"
        + profile.core_namespace
        + "/[a-z0-9./-]+@sha256:[a-f0-9]{64}$"
    )
    rules = [
        ([""], ["pods", "serviceaccounts", "persistentvolumeclaims"]),
        (["batch"], ["jobs"]),
        (["networking.k8s.io"], ["networkpolicies"]),
        (["build.openshift.io"], ["buildconfigs"]),
        (["image.openshift.io"], ["imagestreams"]),
    ]
    checks = [
        (
            "variables.target.metadata.labels['identity-demo-owner'] == "
            + json.dumps(profile.owner)
            + " && variables.target.metadata.labels['app.kubernetes.io/part-of'] == 'identity-demo-preflight'",
            "Recorded installation ownership is required",
        ),
        (
            "request.kind.kind != 'ServiceAccount' || (variables.target.metadata.name == 'fixture-installer-build' && variables.target.automountServiceAccountToken == false)",
            "Only the tokenless compiler ServiceAccount may be created",
        ),
        (
            "request.kind.kind != 'PersistentVolumeClaim' || (variables.target.metadata.name == 'fixture-native-build-state' && variables.target.spec.storageClassName == "
            + json.dumps(profile.storage_class)
            + " && variables.target.spec.accessModes == ['ReadWriteOnce'] && quantity(variables.target.spec.resources.requests.storage).compareTo(quantity('30Gi')) == 0)",
            "Only the bounded native compilation workspace is permitted",
        ),
        (
            "request.kind.kind != 'BuildConfig' || (variables.target.metadata.name in ['fixture-native-compiler','fixture-native-gateway','fixture-native-gateway-bytes','fixture-native-supervisor','fixture-native-supervisor-bytes','fixture-console-runtime'] && variables.target.spec.strategy.type == 'Docker' && variables.target.spec.serviceAccount == 'builder' && variables.target.spec.runPolicy == 'Serial' && (!has(variables.target.spec.triggers) || size(variables.target.spec.triggers) == 0) && !(has(variables.target.spec.source.secrets)) && !(has(variables.target.spec.strategy.dockerStrategy.env)) && !has(variables.target.spec.strategy.dockerStrategy.volumes) && !has(variables.target.spec.strategy.dockerStrategy.pullSecret) && !has(variables.target.spec.source.sourceSecret) && !has(variables.target.spec.source.images) && !has(variables.target.spec.source.configMaps) && variables.target.spec.source.type in ['Binary','Dockerfile'] && !has(variables.target.spec.output.pushSecret) && (!has(variables.target.spec.output.to.namespace) || variables.target.spec.output.to.namespace == request.namespace) && variables.target.spec.output.to.kind == 'ImageStreamTag' && variables.target.spec.output.to.name == variables.target.metadata.name+':candidate')",
            "Only reviewed serial Docker build destinations are permitted",
        ),
        (
            "request.kind.kind != 'ImageStream' || variables.target.metadata.name in ['fixture-native-compiler','fixture-native-gateway','fixture-native-gateway-bytes','fixture-native-supervisor','fixture-native-supervisor-bytes','fixture-console-runtime']",
            "Only reviewed build repositories are permitted",
        ),
        (
            "variables.pod == null || (variables.pod.automountServiceAccountToken == false && (!has(variables.pod.serviceAccountName) || variables.pod.serviceAccountName in ['default','fixture-installer-build']))",
            "Child execution must be tokenless and cannot use installer/runtime identities",
        ),
        (
            "variables.pod == null || ((!has(variables.pod.hostNetwork) || !variables.pod.hostNetwork) && (!has(variables.pod.hostPID) || !variables.pod.hostPID) && (!has(variables.pod.hostIPC) || !variables.pod.hostIPC) && variables.pod.securityContext.runAsNonRoot == true && variables.pod.securityContext.seccompProfile.type == 'RuntimeDefault')",
            "Child execution cannot enter host namespaces or run as root",
        ),
        (
            "variables.pod == null || !has(variables.pod.volumes) || variables.pod.volumes.all(v, has(v.emptyDir) || (has(v.persistentVolumeClaim) && v.persistentVolumeClaim.claimName == 'fixture-native-build-state'))",
            "Child execution cannot mount Secrets, tokens, host paths or application data",
        ),
        (
            "variables.containers.all(c, c.image.matches("
            + json.dumps(regex)
            + ") && c.securityContext.allowPrivilegeEscalation == false && c.securityContext.readOnlyRootFilesystem == true && c.securityContext.capabilities.drop == ['ALL'] && (!has(c.securityContext.capabilities.add) || size(c.securityContext.capabilities.add) == 0) && (!has(c.securityContext.privileged) || !c.securityContext.privileged))",
            "Pinned owned images and restricted container execution are required",
        ),
        (
            "variables.containers.all(c, quantity(c.resources.requests.cpu).compareTo(quantity('0')) > 0 && quantity(c.resources.requests.memory).compareTo(quantity('0')) > 0 && quantity(c.resources.limits.cpu).compareTo(quantity('2')) <= 0 && quantity(c.resources.limits.memory).compareTo(quantity('12Gi')) <= 0)",
            "Child resource requests and limits must remain bounded",
        ),
        (
            "request.kind.kind != 'Pod' || variables.target.metadata.name == 'fixture-native-export'",
            "Only the exact tokenless native-output exporter Pod is permitted",
        ),
        (
            "request.kind.kind != 'Job' || (variables.target.metadata.name.matches('^fixture-(native-(compile|gateway-check|supervisor-check)|check-console-runtime-[a-f0-9]{10})$') && variables.target.spec.backoffLimit == 0 && variables.target.spec.activeDeadlineSeconds <= 2400 && variables.pod.restartPolicy == 'Never')",
            "Child Jobs must have fixed purposes, deadlines and no automatic replay",
        ),
        (
            "request.kind.kind != 'NetworkPolicy' || ((!has(variables.target.spec.egress) || size(variables.target.spec.egress) == 0) && 'Egress' in variables.target.spec.policyTypes && !has(variables.target.spec.podSelector.matchExpressions) && size(variables.target.spec.podSelector.matchLabels) == 1 && ((variables.target.metadata.name == 'fixture-native-offline' && variables.target.spec.podSelector.matchLabels == {'identity-demo-offline-compile':'true'}) || (variables.target.metadata.name.matches('^fixture-runtime-check-[a-f0-9]{10}$') && variables.target.spec.podSelector.matchLabels['identity-demo-runtime-probe'] == variables.target.metadata.labels['identity-demo-runtime-probe'])))",
            "Only isolated build/probe network policies may be created",
        ),
    ]
    checks.append(
        (
            "variables.pod == null || (variables.childLabels['identity-demo-installer-child'] == 'true' && variables.childLabels['identity-demo-owner'] == "
            + json.dumps(profile.owner)
            + ")",
            "Every child must remain selected by the administrator-owned isolation policy",
        )
    )
    policy = resource(
        profile,
        "admissionregistration.k8s.io/v1",
        "ValidatingAdmissionPolicy",
        name,
        spec={
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [
                    {
                        "apiGroups": groups,
                        "apiVersions": ["*"],
                        "operations": ["CREATE", "UPDATE", "DELETE"],
                        "resources": resources,
                    }
                    for groups, resources in rules
                ]
            },
            "matchConditions": [
                {
                    "name": "exact-installer",
                    "expression": "request.userInfo.username == "
                    + json.dumps(principal),
                },
                {
                    "name": "exact-build-namespace",
                    "expression": "request.namespace == "
                    + json.dumps(profile.core_namespace),
                },
            ],
            "variables": [
                {
                    "name": "target",
                    "expression": "request.operation == 'DELETE' ? oldObject : object",
                },
                {
                    "name": "pod",
                    "expression": "request.kind.kind == 'Pod' ? variables.target.spec : request.kind.kind == 'Job' ? variables.target.spec.template.spec : null",
                },
                {
                    "name": "containers",
                    "expression": "variables.pod == null ? [] : variables.pod.containers + (has(variables.pod.initContainers) ? variables.pod.initContainers : [])",
                },
                {
                    "name": "childLabels",
                    "expression": "request.kind.kind == 'Pod' ? variables.target.metadata.labels : request.kind.kind == 'Job' ? variables.target.spec.template.metadata.labels : {}",
                },
            ],
            "validations": [
                {"expression": expression, "message": message}
                for expression, message in checks
            ],
        },
    )
    binding = resource(
        profile,
        "admissionregistration.k8s.io/v1",
        "ValidatingAdmissionPolicyBinding",
        name,
        spec={"policyName": name, "validationActions": ["Deny"]},
    )
    return policy, binding


def bootstrap(value):
    """Render administrator authority only; never install/adopt it implicitly."""
    value = configuration(value)
    profile = DeploymentProfile.from_dict(value["profile"])
    ns = profile.core_namespace
    subject = {
        "kind": "ServiceAccount",
        "name": "fixture-installer-build-operator",
        "namespace": ns,
    }
    name = "identity-demo-" + profile.installation_id + "-installer-build"

    def rule(group, resources, verbs, names=None):
        item = {"apiGroups": [group], "resources": resources, "verbs": verbs}
        if names is not None:
            item["resourceNames"] = names
        return item

    builds = [
        "fixture-native-compiler",
        "fixture-native-gateway",
        "fixture-native-gateway-bytes",
        "fixture-native-supervisor",
        "fixture-native-supervisor-bytes",
        "fixture-console-runtime",
    ]
    local = [
        rule(
            "coordination.k8s.io",
            ["leases"],
            ["get", "update"],
            ["fixture-installer-build-operator"],
        ),
        rule("", ["serviceaccounts"], ["create"]),
        rule("", ["serviceaccounts"], ["get"], ["fixture-installer-build"]),
        rule("", ["pods"], ["get", "list", "create", "delete"]),
        rule("", ["pods/log"], ["get"]),
        rule("", ["pods/exec"], ["create"], ["fixture-native-export"]),
        rule("", ["persistentvolumeclaims"], ["create"]),
        rule("", ["persistentvolumeclaims"], ["get"], ["fixture-native-build-state"]),
        rule("batch", ["jobs"], ["create", "get", "list", "delete"]),
        rule(
            "networking.k8s.io",
            ["networkpolicies"],
            ["create", "get", "list", "delete"],
        ),
        rule("build.openshift.io", ["buildconfigs"], ["create"]),
        rule("build.openshift.io", ["buildconfigs"], ["get"], builds),
        rule(
            "build.openshift.io",
            ["buildconfigs/instantiatebinary", "buildconfigs/instantiate"],
            ["create"],
            builds,
        ),
        rule("build.openshift.io", ["builds"], ["get", "list"]),
        rule("image.openshift.io", ["imagestreams"], ["create"]),
        rule("image.openshift.io", ["imagestreams"], ["get"], builds),
    ]
    global_rules = [
        rule(
            "",
            ["namespaces"],
            ["get"],
            [*profile.application_namespaces, profile.identity_namespace],
        ),
        rule(
            "apiextensions.k8s.io",
            ["customresourcedefinitions"],
            ["get"],
            [
                "sandboxes.agents.x-k8s.io",
                "clusterstaticentries.spire.spiffe.io",
                "clusterspiffeids.spire.spiffe.io",
                "gateways.gateway.networking.k8s.io",
                "httproutes.gateway.networking.k8s.io",
                "authpolicies.kuadrant.io",
                "mcpgatewayextensions.mcp.kuadrant.io",
                "mcpserverregistrations.mcp.kuadrant.io",
                "envoyfilters.networking.istio.io",
                "certificates.cert-manager.io",
            ],
        ),
        rule(
            "operator.openshift.io",
            ["zerotrustworkloadidentitymanagers"],
            ["get"],
            ["cluster"],
        ),
        rule("storage.k8s.io", ["storageclasses"], ["get"], [profile.storage_class]),
    ]
    policy = value["certificate_management"]
    if policy["mode"] == "managed":
        ref = policy["issuer_ref"]
        (local if ref["kind"] == "Issuer" else global_rules).append(
            rule(
                "cert-manager.io",
                ["issuers" if ref["kind"] == "Issuer" else "clusterissuers"],
                ["get"],
                [ref["name"]],
            )
        )
        local.append(
            rule(
                "",
                ["secrets"],
                ["get"],
                [
                    "fixture-openshell-server-tls",
                    "fixture-openshell-client-tls",
                    "fixture-mcp-bound-mutual",
                ],
            )
        )
    proposed = [
        resource(
            profile,
            "v1",
            "ServiceAccount",
            "fixture-installer-build-operator",
            ns,
            automountServiceAccountToken=False,
        ),
        resource(
            profile,
            "coordination.k8s.io/v1",
            "Lease",
            "fixture-installer-build-operator",
            ns,
            spec={"leaseDurationSeconds": 45},
        ),
        resource(
            profile,
            "v1",
            "PersistentVolumeClaim",
            "fixture-installer-state",
            ns,
            spec={
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": profile.storage_class,
                "resources": {"requests": {"storage": "10Gi"}},
            },
        ),
        resource(
            profile, "rbac.authorization.k8s.io/v1", "Role", name, ns, rules=local
        ),
        resource(
            profile,
            "rbac.authorization.k8s.io/v1",
            "RoleBinding",
            name,
            ns,
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": name,
            },
            subjects=[subject],
        ),
        resource(
            profile,
            "rbac.authorization.k8s.io/v1",
            "ClusterRole",
            name,
            rules=global_rules,
        ),
        resource(
            profile,
            "rbac.authorization.k8s.io/v1",
            "ClusterRoleBinding",
            name,
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": name,
            },
            subjects=[subject],
        ),
    ]
    proposed.append(
        resource(
            profile,
            "v1",
            "ResourceQuota",
            "fixture-installer-build-budget",
            ns,
            spec={
                "hard": {
                    "requests.cpu": "4",
                    "limits.cpu": "6",
                    "requests.memory": "16Gi",
                    "limits.memory": "20Gi",
                    "requests.storage": "40Gi",
                    "persistentvolumeclaims": "2",
                    "pods": "8",
                }
            },
        )
    )
    # This build-only quota is retired by its original UID after successful
    # builds, before the separately reviewed application budget is activated.
    from urllib.parse import urlsplit

    proposed.append(
        resource(
            profile,
            "networking.k8s.io/v1",
            "NetworkPolicy",
            "fixture-installer-transport",
            ns,
            spec={
                "podSelector": {
                    "matchLabels": {
                        "app": "fixture-installer",
                        "identity-demo-owner": profile.owner,
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [
                    {
                        "to": [
                            {"ipBlock": {"cidr": c}}
                            for c in value["kubernetes_api_cidrs"]
                        ],
                        "ports": [
                            {
                                "protocol": "TCP",
                                "port": urlsplit(profile.expected_server).port or 443,
                            }
                        ],
                    },
                    {
                        "to": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "openshift-dns"
                                    }
                                }
                            }
                        ],
                        "ports": [
                            {"protocol": protocol, "port": port}
                            for protocol in ("TCP", "UDP")
                            for port in (53, 5353)
                        ],
                    },
                ],
            },
        )
    )
    proposed.append(
        resource(
            profile,
            "networking.k8s.io/v1",
            "NetworkPolicy",
            "fixture-installer-child-isolation",
            ns,
            spec={
                "podSelector": {
                    "matchLabels": {
                        "identity-demo-installer-child": "true",
                        "identity-demo-owner": profile.owner,
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        )
    )
    route_name = name + "-ingress-read"
    proposed += [
        resource(
            profile,
            "rbac.authorization.k8s.io/v1",
            "Role",
            route_name,
            "openshift-ingress",
            rules=[rule("", ["services"], ["get"], ["router-default"])],
        ),
        resource(
            profile,
            "rbac.authorization.k8s.io/v1",
            "RoleBinding",
            route_name,
            "openshift-ingress",
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": route_name,
            },
            subjects=[subject],
        ),
    ]
    return [*proposed, *boundary(profile)]


def build_job(value, image, *, phase="build", ingress_address=None):
    """One bounded installer, with projected API authentication and durable state."""
    value = configuration(value)
    if phase not in ("build", "application"):
        raise ValueError("Explicit installer phase required")
    profile = DeploymentProfile.from_dict(value["profile"])
    if not IMAGE_REFERENCE.fullmatch(image) or image.endswith("0" * 64):
        raise ValueError("Exact reviewed installer image digest required")
    ns = profile.core_namespace
    security = {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    pod = {
        "serviceAccountName": "fixture-installer-build-operator"
        if phase == "build"
        else "fixture-installer",
        "automountServiceAccountToken": False,
        "restartPolicy": "Never",
        "nodeSelector": {"kubernetes.io/arch": "amd64"},
        "securityContext": {
            "runAsNonRoot": True,
            # Preserve mode-0600 checkpoints when the next phase mounts the PVC.
            "fsGroupChangePolicy": "OnRootMismatch",
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [
            {
                "name": "installer",
                "image": image,
                "securityContext": security,
                "command": [
                    "/bin/sh",
                    "-ec",
                    "umask 077; mkdir /tmp/private; exec python3.12 /app/scripts/identity_demo/identity_demo_setup.py installer-"
                    + phase
                    + "-session --output-dir /tmp/private/result --apply",
                ],
                "env": [
                    {
                        "name": "POD_UID",
                        "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}},
                    },
                    {
                        "name": "POD_NAMESPACE",
                        "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}},
                    },
                ],
                "resources": {
                    "requests": {"cpu": "100m", "memory": "256Mi"},
                    "limits": {"cpu": "1", "memory": "2Gi"},
                },
                "volumeMounts": [
                    {"name": name, "mountPath": mount, "readOnly": True}
                    for name, mount in (
                        ("inputs", "/inputs"),
                        ("credentials", "/credentials"),
                        ("receipts", "/receipts"),
                        ("public-trust", "/public-trust"),
                        ("api-token", "/var/run/secrets/kubernetes.io/serviceaccount"),
                    )
                ]
                + [
                    {"name": "state", "mountPath": "/state"},
                    {"name": "tmp", "mountPath": "/tmp"},
                ],
            }
        ],
        "volumes": [
            {
                "name": "inputs",
                "configMap": {
                    "name": "fixture-installer-configuration",
                    "defaultMode": 0o440,
                },
            },
            {
                "name": "public-trust",
                "configMap": {"name": "fixture-installer-trust", "defaultMode": 0o440},
            },
            {
                "name": "credentials",
                "secret": {
                    "secretName": "fixture-installer-inference",
                    "defaultMode": 0o440,
                    "items": [{"key": "api-key", "path": "inference.key"}],
                },
            },
            {
                "name": "receipts",
                "configMap": {
                    "name": "fixture-installer-namespace-receipts"
                    if phase == "build"
                    else "fixture-installer-application-receipts",
                    "defaultMode": 0o440,
                },
            },
            {
                "name": "api-token",
                "projected": {
                    "defaultMode": 0o440,
                    "sources": [
                        {
                            "serviceAccountToken": {
                                "expirationSeconds": 3600,
                                "path": "token",
                            }
                        },
                        {
                            "configMap": {
                                "name": "kube-root-ca.crt",
                                "items": [{"key": "ca.crt", "path": "ca.crt"}],
                            }
                        },
                    ],
                },
            },
            {
                "name": "state",
                "persistentVolumeClaim": {"claimName": "fixture-installer-state"},
            },
            {"name": "tmp", "emptyDir": {"sizeLimit": "1Gi"}},
        ],
    }
    pod["containers"][0]["env"].append(
        {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}
    )
    if ingress_address is not None:
        from ipaddress import ip_address

        address = ip_address(ingress_address)
        if phase != "application" or address.is_unspecified or address.is_multicast:
            raise ValueError("Verified internal application ingress address required")
        pod["hostAliases"] = [
            {
                "ip": str(address),
                "hostnames": [
                    profile.origin(name).removeprefix("https://")
                    for name in ("fixture-keycloak", "fixture-keycloak-upstream")
                ],
            }
        ]
    return resource(
        profile,
        "batch/v1",
        "Job",
        "fixture-installer-" + phase + "-session",
        ns,
        spec={
            "backoffLimit": 0,
            "activeDeadlineSeconds": 7200,
            "template": {
                "metadata": {
                    "labels": dict(
                        profile.labels,
                        app="fixture-installer",
                        **{"identity-demo-installer-phase": phase},
                    )
                },
                "spec": pod,
            },
        },
    )


def plan(args):
    """Tokenless public bootstrap rendering; applying authority remains explicit."""
    import base64
    from pathlib import Path
    from identity_demo_cluster_bootstrap import mounted
    from source_render import read_json

    if args.apply:
        raise ValueError("Bootstrap planning cannot apply authority")
    path = args.output_dir / "received.configuration.json"
    with path.open("xb") as stream:
        import os

        os.chmod(path, 0o600)
        stream.write(mounted(Path("/inputs"), "installation.json"))
    value = configuration(read_json(path))
    image = args.installer_image
    profile = DeploymentProfile.from_dict(value["profile"])
    if not IMAGE_REFERENCE.fullmatch(image) or not image.startswith(
        "image-registry.openshift-image-registry.svc:5000/"
        + profile.core_namespace
        + "-build/"
    ):
        raise ValueError("Reviewed owned immutable installer image required")
    objects = [
        *namespace_objects(profile),
        *bootstrap(value),
        *installer_pull_grants(profile, image, value.get("native_builder_image")),
    ]
    for index, obj in enumerate(objects):
        encoded = base64.b64encode(json.dumps(obj, sort_keys=True).encode()).decode()
        print("BOOTSTRAP_RESOURCE=" + str(index) + ":" + encoded, flush=True)
    print(
        "BUILD_JOB="
        + base64.b64encode(
            json.dumps(build_job(value, image), sort_keys=True).encode()
        ).decode(),
        flush=True,
    )
    return {
        "bootstrap_plan_rendered": True,
        "resources": len(objects),
        "cluster_changed": False,
        "application_installed": False,
        "administrator_review_required": True,
    }
