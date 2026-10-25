# SPDX-License-Identifier: Apache-2.0
"""Administrator-reviewed application authority, separate from build submission.

Only the three owned namespaces are writable. Registration, RBAC, admission,
issuer signing keys and build submission remain administrator responsibilities.
"""

import json
from collections import defaultdict

from cluster_console_resources import ingress_peer, resource, workloads
from deployment_artifacts import IMAGE_REFERENCE
import identity_demo_setup as setup

APIS = dict(
    setup.APIS,
    AuthConfig="authorino.kuadrant.io/v1beta3",
    LimitRange="v1",
    ResourceQuota="v1",
    Lease="coordination.k8s.io/v1",
)
RESOURCES = dict(
    setup.RESOURCES,
    AuthConfig="authconfigs.authorino.kuadrant.io",
    LimitRange="limitranges",
    ResourceQuota="resourcequotas",
    Lease="leases.coordination.k8s.io",
)


def authority(
    profile,
    application,
    prerequisites,
    artifacts,
    runtime_image,
    value,
    ingress_address=None,
):
    """Bind application creation and mounts to the reviewed installation inputs."""
    if not IMAGE_REFERENCE.fullmatch(runtime_image):
        raise ValueError("Pinned verified worker runtime required")
    ns = profile.core_namespace
    principal = "system:serviceaccount:" + ns + ":fixture-installer"
    subject = {"kind": "ServiceAccount", "name": "fixture-installer", "namespace": ns}
    prefix = "identity-demo-" + profile.installation_id + "-installer-application"
    allowed = defaultdict(set)
    for obj in application:
        if obj["metadata"].get("namespace") == ns:
            allowed[obj["kind"]].add(obj["metadata"]["name"])
    for kind, names in {
        "Secret": [
            "fixture-identity-driver-tls",
            "fixture-identity-operator-tls",
            "fixture-jira-rest-tls",
            "fixture-protected-adapter-tls",
            "fixture-keycloak-upstream-tls",
            "fixture-console-role-credentials",
            "fixture-console-coordinator-inputs",
            "fixture-console-preparer-inputs",
            "fixture-step4-read-route",
            "fixture-step4-read-route-ca",
            "fixture-step4-read-route-catalog",
            "fixture-openshell-server-client-ca",
        ],
        "ConfigMap": ["fixture-console-sender-trust", "fixture-step4-retired-runs"],
        "Service": ["fixture-identity-operator"],
        "NetworkPolicy": [
            "fixture-identity-operator",
            "fixture-driver-issue-view",
            "fixture-adapter-issue-view",
            "fixture-driver-business",
            "fixture-driver-issuer-egress",
            "fixture-driver-issuer-ingress",
            "fixture-console-coordinator",
            "fixture-console-preparer",
        ],
        "Deployment": ["fixture-console-coordinator", "fixture-console-preparer"],
        "PersistentVolumeClaim": [
            "fixture-console-coordinator-state",
            "fixture-console-preparer-state",
        ],
        "HTTPRoute": ["fixture-step4-read-route"],
        "AuthPolicy": ["fixture-step4-read-route"],
        "EnvoyFilter": [
            "fixture-step4-read-route",
            "fixture-step4-read-route-authorino-tls",
            "fixture-step4-read-route-router",
            "fixture-step56-live-identity",
        ],
        "AuthConfig": ["fixture-step4-read-route", "fixture-step56-live-identity"],
        "MCPServerRegistration": ["fixture-step4-read-route"],
    }.items():
        allowed[kind].update(names)
    if any("fixture-application-ca" in names for names in allowed.values()):
        raise ValueError("Issuer signing material cannot enter installer authority")
    for key in ("Namespace", "ServiceAccount", "Role", "RoleBinding"):
        allowed.pop(key, None)
    controllers = [o for o in application if o["kind"] in setup.CONTROLLERS]
    controllers += [
        o
        for o in workloads(profile, runtime_image, ["192.0.2.1/32"])
        if o["kind"] in setup.CONTROLLERS
    ]
    mounts = {}
    for obj in controllers:
        pod = obj["spec"]["template"]["spec"]
        secrets = {
            v["secret"]["secretName"] for v in pod.get("volumes", []) if "secret" in v
        }
        claims = {
            v["persistentVolumeClaim"]["claimName"]
            for v in pod.get("volumes", [])
            if "persistentVolumeClaim" in v
        }
        if obj["metadata"]["name"] == "fixture-identity-driver":
            secrets.update(
                {"fixture-identity-operator-tls", "fixture-console-role-credentials"}
            )
        environment, sources = defaultdict(set), set()
        for container in pod.get("containers", []) + pod.get("initContainers", []):
            for entry in container.get("env", []):
                reference = entry.get("valueFrom", {}).get("secretKeyRef")
                if reference:
                    environment[reference["name"]].add(reference["key"])
            sources.update(entry["secretRef"]["name"] for entry in container.get("envFrom", [])
                           if "secretRef" in entry)
        registered = allowed["Secret"] | {
            o["spec"]["secretName"] for o in application if o["kind"] == "Certificate"}
        if (set(environment) | sources) - registered:
            raise ValueError("Environment credentials must reference registered application Secrets")
        mounts[obj["metadata"]["name"]] = {
            "account": pod.get("serviceAccountName", "default"),
            "secrets": sorted(secrets),
            "claims": sorted(claims),
            "environment": {name: sorted(keys) for name, keys in environment.items()},
            "sources": sorted(sources),
        }
    images = sorted(set(artifacts["images"].values()) | {runtime_image})
    routes = {}
    for obj in (o for o in application if o["kind"] == "Route"):
        spec, tls = obj["spec"], obj["spec"]["tls"]
        if (obj["metadata"].get("namespace") != ns
                or set(spec) - {"host", "port", "tls", "to", "wildcardPolicy", "path"}
                or set(tls) - {"termination", "insecureEdgeTerminationPolicy", "destinationCACertificate"}
                or spec["to"] != {"kind": "Service", "name": spec["to"]["name"], "weight": 100}
                or spec.get("wildcardPolicy", "None") != "None"
                or type(spec["port"]["targetPort"]) not in (str, int)):
            raise ValueError("Fixed core Service routes with platform TLS are required")
        # CEL literal maps require homogeneous values. Pin scalar fields rather
        # than permit arbitrary nested specs, inline keys or alternate backends.
        routes[obj["metadata"]["name"]] = {
            "host": spec["host"], "service": spec["to"]["name"],
            "port": str(spec["port"]["targetPort"]),
            "port_kind": "int" if type(spec["port"]["targetPort"]) is int else "string",
            "termination": tls["termination"],
            "insecure": tls.get("insecureEdgeTerminationPolicy", ""),
            "destination_ca": tls.get("destinationCACertificate", ""),
            "path": spec.get("path", ""),
        }
    # Workers observe public leaves through key-filtered projections, never keys.
    public_leaf = (
        "has(s.secret) && variables.target.metadata.name in ['fixture-console-coordinator','fixture-console-preparer']"
        " && v.name == 'application-certificates' && has(v.projected.defaultMode) && v.projected.defaultMode == 292"
        " && s.secret.name in variables.certificateSecrets && has(s.secret.items) && size(s.secret.items) == 1"
        " && s.secret.items[0].key == 'tls.crt' && s.secret.items[0].path == s.secret.name + '.crt'"
        " && (!has(s.secret.items[0].mode) || s.secret.items[0].mode == 292)"
        " && (!has(s.secret.optional) || s.secret.optional == false)"
    )
    checks = [
        (
            "variables.target.metadata.labels['identity-demo-owner'] == "
            + json.dumps(profile.owner),
            "Exact installation ownership is required",
        ),
        (
            "variables.target.metadata.name in variables.names[request.kind.kind] || (request.kind.kind == 'ConfigMap' && variables.target.metadata.name.matches('^fixture-(identity-driver-code|adapter-action-code)-[a-f0-9]{10}$')) || (request.dryRun == true && request.operation == 'CREATE' && request.kind.kind == 'ConfigMap' && variables.target.metadata.name == 'fixture-console-sender-trust-review')",
            "Only reviewed application destinations may be changed",
        ),
        (
            "variables.pod == null || variables.target.metadata.name in variables.accounts",
            "Only reviewed application controllers may run containers",
        ),
        (
            "variables.pod == null || ((!has(variables.pod.hostNetwork) || !variables.pod.hostNetwork) && (!has(variables.pod.hostPID) || !variables.pod.hostPID) && (!has(variables.pod.hostIPC) || !variables.pod.hostIPC) && variables.pod.securityContext.runAsNonRoot == true)",
            "Host access and root execution are forbidden",
        ),
        (
            "variables.pod == null || (has(variables.pod.serviceAccountName) ? variables.pod.serviceAccountName : 'default') == variables.accounts[variables.target.metadata.name]",
            "Application ServiceAccounts cannot be substituted with installer or other identities",
        ),
        (
            "variables.pod == null || (variables.target.metadata.name == 'fixture-openshell' || variables.pod.automountServiceAccountToken == false)",
            "Only the reviewed native gateway may use automatic API authentication",
        ),
        (
            "variables.pod == null || !has(variables.pod.volumes) || variables.pod.volumes.all(v, has(v.emptyDir) || has(v.configMap) || (has(v.secret) && v.secret.secretName in variables.secretMounts[variables.target.metadata.name]) || (has(v.persistentVolumeClaim) && v.persistentVolumeClaim.claimName in variables.claimMounts[variables.target.metadata.name]) || (has(v.projected) && v.projected.sources.all(s, has(s.serviceAccountToken) || has(s.configMap) || has(s.downwardAPI) || (" + public_leaf + "))) || (variables.target.metadata.name == 'fixture-openshell' && has(v.csi) && v.csi.driver == 'csi.spiffe.io' && v.csi.readOnly == true))",
            "Only reviewed data and credentials may be mounted; signing keys and installer state are excluded",
        ),
        (
            "variables.containers.all(c, c.image in variables.images && (!has(c.securityContext.privileged) || !c.securityContext.privileged) && c.securityContext.allowPrivilegeEscalation == false && c.securityContext.capabilities.drop == ['ALL'] && (!has(c.securityContext.capabilities.add) || size(c.securityContext.capabilities.add) == 0))",
            "Reviewed immutable images and restricted containers are required",
        ),
        (
            "variables.containers.all(c, (!has(c.envFrom) || c.envFrom.all(e, has(e.configMapRef) || (has(e.secretRef) && e.secretRef.name in variables.secretEnvFrom[variables.target.metadata.name]))) && (!has(c.env) || c.env.all(e, !has(e.valueFrom) || !has(e.valueFrom.secretKeyRef) || (e.valueFrom.secretKeyRef.name in variables.secretEnv[variables.target.metadata.name] && e.valueFrom.secretKeyRef.key in variables.secretEnv[variables.target.metadata.name][e.valueFrom.secretKeyRef.name]))))",
            "Environment references cannot expose unapproved Secrets",
        ),
        (
            "request.kind.kind != 'Route' || (variables.target.spec.host == variables.routes[variables.target.metadata.name].host && variables.target.spec.to.kind == 'Service' && variables.target.spec.to.name == variables.routes[variables.target.metadata.name].service && variables.target.spec.to.weight == 100 && string(variables.target.spec.port.targetPort) == variables.routes[variables.target.metadata.name].port && (type(variables.target.spec.port.targetPort) == int ? 'int' : 'string') == variables.routes[variables.target.metadata.name].port_kind && variables.target.spec.tls.termination == variables.routes[variables.target.metadata.name].termination && (has(variables.target.spec.tls.insecureEdgeTerminationPolicy) ? variables.target.spec.tls.insecureEdgeTerminationPolicy : '') == variables.routes[variables.target.metadata.name].insecure && (has(variables.target.spec.tls.destinationCACertificate) ? variables.target.spec.tls.destinationCACertificate : '') == variables.routes[variables.target.metadata.name].destination_ca && !has(variables.target.spec.tls.key) && !has(variables.target.spec.tls.certificate) && !has(variables.target.spec.tls.caCertificate) && !has(variables.target.spec.tls.externalCertificate) && (has(variables.target.spec.path) ? variables.target.spec.path : '') == variables.routes[variables.target.metadata.name].path && (!has(variables.target.spec.subdomain) || variables.target.spec.subdomain == '') && (!has(variables.target.spec.alternateBackends) || size(variables.target.spec.alternateBackends) == 0) && !has(variables.target.spec.httpHeaders) && variables.target.spec.wildcardPolicy == 'None')",
            "Route hostname, backend and TLS must match the reviewed application contract",
        ),
        (
            "request.kind.kind != 'Certificate' || (variables.target.spec.issuerRef == variables.issuer && variables.target.spec.secretName in variables.certificateSecrets)",
            "Certificate issuance is limited to the reviewed issuer and application leaves",
        ),
    ]
    certificates = [o for o in application if o["kind"] == "Certificate"]
    issuer = certificates[0]["spec"]["issuerRef"] if certificates else {}
    if any(o["spec"]["issuerRef"] != issuer for o in certificates):
        raise ValueError("One approved issuer contract required")
    certificate_cases = []
    for obj in certificates:
        spec = obj["spec"]
        conditions = [
            "variables.target.metadata.name == " + json.dumps(obj["metadata"]["name"]),
            "!has(variables.target.spec.isCA) || variables.target.spec.isCA == false",
            "variables.target.spec.commonName == " + json.dumps(spec["commonName"])
            if "commonName" in spec
            else "!has(variables.target.spec.commonName)",
        ]
        for field in ("secretName", "issuerRef"):
            conditions.append(
                "variables.target.spec." + field + " == " + json.dumps(spec[field])
            )
        for field in ("duration", "renewBefore"):
            conditions.append(
                "duration(variables.target.spec."
                + field
                + ") == duration("
                + json.dumps(spec[field])
                + ")"
            )
        for field in ("dnsNames", "ipAddresses", "uris", "usages"):
            conditions.append(
                "(has(variables.target.spec."
                + field
                + ") ? variables.target.spec."
                + field
                + " : []) == "
                + json.dumps(spec.get(field, []))
            )
        for field, expected in spec.get("privateKey", {}).items():
            conditions.append(
                "variables.target.spec.privateKey."
                + field
                + " == "
                + json.dumps(expected)
            )
        certificate_cases.append(
            "(" + " && ".join("(" + c + ")" for c in conditions) + ")"
        )
    checks.append(
        (
            "request.kind.kind != 'Certificate' || ("
            + (" || ".join(certificate_cases) or "false")
            + ")",
            "Certificate identity, lifetime, usage and key rotation must match the reviewed leaf contract",
        )
    )
    policy = resource(
        profile,
        "admissionregistration.k8s.io/v1",
        "ValidatingAdmissionPolicy",
        prefix,
        spec={
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [
                    {
                        "apiGroups": sorted(
                            {
                                APIS[k].split("/")[0] if "/" in APIS[k] else ""
                                for k in allowed
                            }
                        ),
                        "apiVersions": ["*"],
                        "operations": ["CREATE", "UPDATE", "DELETE"],
                        "resources": sorted(
                            {RESOURCES[k].split(".")[0] for k in allowed}
                        ),
                    }
                ]
            },
            "matchConditions": [
                {
                    "name": "exact-installer",
                    "expression": "request.userInfo.username == "
                    + json.dumps(principal),
                },
                {
                    "name": "exact-core",
                    "expression": "request.namespace == " + json.dumps(ns),
                },
            ],
            "variables": [
                {
                    "name": "target",
                    "expression": "request.operation == 'DELETE' ? oldObject : object",
                },
                {
                    "name": "names",
                    "expression": json.dumps(
                        {k: sorted(v) for k, v in allowed.items()}
                    ),
                },
                {
                    "name": "accounts",
                    "expression": json.dumps(
                        {k: v["account"] for k, v in mounts.items()}
                    ),
                },
                {
                    "name": "secretMounts",
                    "expression": json.dumps(
                        {k: v["secrets"] for k, v in mounts.items()}
                    ),
                },
                {
                    "name": "secretEnv",
                    "expression": json.dumps({k: v["environment"] for k, v in mounts.items()}),
                },
                {
                    "name": "secretEnvFrom",
                    "expression": json.dumps({k: v["sources"] for k, v in mounts.items()}),
                },
                {
                    "name": "claimMounts",
                    "expression": json.dumps(
                        {k: v["claims"] for k, v in mounts.items()}
                    ),
                },
                {"name": "images", "expression": json.dumps(images)},
                {"name": "routes", "expression": json.dumps(routes)},
                {"name": "issuer", "expression": json.dumps(issuer)},
                {
                    "name": "certificateSecrets",
                    "expression": json.dumps(
                        sorted(o["spec"]["secretName"] for o in certificates)
                    ),
                },
                {
                    "name": "pod",
                    "expression": "request.kind.kind in ['Deployment','StatefulSet'] ? variables.target.spec.template.spec : null",
                },
                {
                    "name": "containers",
                    "expression": "variables.pod == null ? [] : variables.pod.containers + (has(variables.pod.initContainers) ? variables.pod.initContainers : [])",
                },
            ],
            "validations": [{"expression": a, "message": b} for a, b in checks],
        },
    )
    binding = resource(
        profile,
        "admissionregistration.k8s.io/v1",
        "ValidatingAdmissionPolicyBinding",
        prefix,
        spec={"policyName": prefix, "validationActions": ["Deny"]},
    )
    rules = []
    for kind, names in allowed.items():
        group = APIS[kind].split("/")[0] if "/" in APIS[kind] else ""
        res = RESOURCES[kind].split(".")[0]
        rules.append({"apiGroups": [group], "resources": [res], "verbs": ["create"]})
        # Hash-addressed immutable code is verified by existing creation ledgers;
        # RBAC cannot express a name prefix. Admission supplies that restriction.
        read_names = {} if kind == "ConfigMap" else {"resourceNames": sorted(names)}
        rules.append(
            {
                "apiGroups": [group],
                "resources": [res],
                "verbs": ["get", "patch", "update", "delete"],
                **read_names,
            }
        )
    if routes:
        # OpenShift checks this subresource when a caller sets spec.host.
        # The admission contract above pins every complete Route specification.
        rules.append({"apiGroups": ["route.openshift.io"],
                      "resources": ["routes/custom-host"], "verbs": ["create"]})
    for obj in prerequisites:
        meta = obj["metadata"]
        if meta.get("namespace") == ns and obj["kind"] in {
            "Role",
            "RoleBinding",
            "ServiceAccount",
            "Lease",
            "LimitRange",
            "ResourceQuota",
        }:
            kind = obj["kind"]
            res = {
                "Lease": "leases",
                "LimitRange": "limitranges",
                "ResourceQuota": "resourcequotas",
            }.get(kind, RESOURCES.get(kind, ""))
            group = {"Lease": "coordination.k8s.io"}.get(
                kind,
                APIS.get(kind, "v1").split("/")[0]
                if "/" in APIS.get(kind, "v1")
                else "",
            )
            rules.append(
                {
                    "apiGroups": [group],
                    "resources": [res.split(".")[0]],
                    "resourceNames": [meta["name"]],
                    "verbs": ["get"],
                }
            )
    rules += [
        {
            "apiGroups": ["networking.istio.io"],
            "resources": ["envoyfilters"],
            "verbs": ["get", "list"],
        },
        {
            "apiGroups": ["authorino.kuadrant.io"],
            "resources": ["authconfigs"],
            "verbs": ["get", "list"],
        },
        {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get", "list"]},
        # Verify the gateway Pod's exact controller ownership chain.
        {"apiGroups": ["apps"], "resources": ["replicasets"], "verbs": ["get"]},
        {
            "apiGroups": ["image.openshift.io"],
            "resources": ["imagestreams"],
            "resourceNames": ["fixture-native-supervisor"],
            "verbs": ["get"],
        },
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
        {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]},
        {
            "apiGroups": [""],
            "resources": ["pods/exec", "pods/portforward"],
            "verbs": ["create"],
        },
        {
            "apiGroups": ["coordination.k8s.io"],
            "resources": ["leases"],
            "resourceNames": ["fixture-installer"],
            "verbs": ["get", "update"],
        },
        {
            "apiGroups": [""],
            "resources": ["resourcequotas"],
            "resourceNames": ["fixture-installer-build-budget"],
            "verbs": ["get"],
        },
        {
            "apiGroups": ["rbac.authorization.k8s.io"],
            "resources": ["rolebindings"],
            "resourceNames": [
                "identity-demo-" + profile.installation_id + "-installer-build"
            ],
            "verbs": ["get"],
        },
    ]
    certificate_policy = value["certificate_management"]
    if certificate_policy["mode"] == "managed":
        # Observe only the approved issuer and issued leaves, never its signer.
        if certificate_policy["issuer_ref"]["kind"] == "Issuer":
            rules.append(
                {
                    "apiGroups": ["cert-manager.io"],
                    "resources": ["issuers"],
                    "resourceNames": [certificate_policy["issuer_ref"]["name"]],
                    "verbs": ["get"],
                }
            )
        from managed_certificates import SECRETS

        rules.append(
            {
                "apiGroups": [""],
                "resources": ["secrets"],
                "resourceNames": list(SECRETS),
                "verbs": ["get"],
            }
        )
    from cluster_installer_resources import bootstrap

    global_rules = next(
        o["rules"] for o in bootstrap(value) if o["kind"] == "ClusterRole"
    )
    group_resources = {
        "ClusterSPIFFEID": ("spire.spiffe.io", "clusterspiffeids"),
        "ClusterRole": ("rbac.authorization.k8s.io", "clusterroles"),
        "ClusterRoleBinding": ("rbac.authorization.k8s.io", "clusterrolebindings"),
        "ValidatingAdmissionPolicy": (
            "admissionregistration.k8s.io",
            "validatingadmissionpolicies",
        ),
        "ValidatingAdmissionPolicyBinding": (
            "admissionregistration.k8s.io",
            "validatingadmissionpolicybindings",
        ),
    }
    scoped = defaultdict(list)
    for obj in prerequisites:
        kind, meta = obj["kind"], obj["metadata"]
        if kind in group_resources:
            group, res = group_resources[kind]
            global_rules.append(
                {
                    "apiGroups": [group],
                    "resources": [res],
                    "resourceNames": [meta["name"]],
                    "verbs": ["get"],
                }
            )
        elif meta.get("namespace") == profile.identity_namespace:
            # The administrator verifies its own exact public-trust RBAC
            # before launch. The installer can read only the public bundle.
            expected = (
                "fixture-console-coordinator-public-trust-" + profile.installation_id
            )
            permitted = (
                kind in ("Role", "RoleBinding") and meta["name"] == expected
            ) or (
                kind == "NetworkPolicy"
                and meta["name"]
                == "identity-demo-" + profile.installation_id + "-discovery-access"
            )
            if not permitted:
                raise ValueError("Unapproved shared prerequisite observation")
            continue
        elif meta.get("namespace") and meta["namespace"] != ns:
            group = (
                APIS.get(kind, "v1").split("/")[0]
                if "/" in APIS.get(kind, "v1")
                else ""
            )
            if kind not in RESOURCES:
                raise ValueError("Unrecognized namespaced prerequisite")
            scoped[meta["namespace"]].append(
                {
                    "apiGroups": [group],
                    "resources": [RESOURCES[kind].split(".")[0]],
                    "resourceNames": [meta["name"]],
                    "verbs": ["get"],
                }
            )
    scoped[profile.identity_namespace].append(
        {
            "apiGroups": [""],
            "resources": ["configmaps"],
            "resourceNames": ["spire-bundle"],
            "verbs": ["get"],
        }
    )
    scoped["openshift-ingress"].append(
        {
            "apiGroups": [""],
            "resources": ["services"],
            "resourceNames": ["router-default"],
            "verbs": ["get"],
        }
    )
    # Refuse gateway replacement while any native context remains. This
    # inventory read is limited to this installation's workspace namespaces.
    for namespace in profile.application_namespaces[1:]:
        scoped[namespace].append({
            "apiGroups": ["agents.x-k8s.io"],
            "resources": ["sandboxes"],
            "verbs": ["list"],
        })
        scoped[namespace].append({
            "apiGroups": [""],
            "resources": ["resourcequotas"],
            "verbs": ["list"],
        })
    extra = []
    for namespace, reads in scoped.items():
        extra += [
            resource(
                profile,
                "rbac.authorization.k8s.io/v1",
                "Role",
                prefix,
                namespace,
                rules=reads,
            ),
            resource(
                profile,
                "rbac.authorization.k8s.io/v1",
                "RoleBinding",
                prefix,
                namespace,
                roleRef={
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": prefix,
                },
                subjects=[subject],
            ),
        ]
    if ingress_address is not None:
        from ipaddress import ip_address

        address = ip_address(ingress_address)
        if address.is_unspecified or address.is_multicast:
            raise ValueError("Verified internal ingress destination required")
        extra.append(
            resource(
                profile,
                "networking.k8s.io/v1",
                "NetworkPolicy",
                prefix + "-transport",
                ns,
                spec={
                    "podSelector": {
                        "matchLabels": {
                            "app": "fixture-installer",
                            "identity-demo-installer-phase": "application",
                            "identity-demo-owner": profile.owner,
                        }
                    },
                    "policyTypes": ["Egress"],
                    "egress": [
                        {
                            "to": [ingress_peer()],
                            "ports": [{"protocol": "TCP", "port": 443}],
                        },
                        {
                            "to": [{"podSelector": {}}],
                            "ports": [
                                {"protocol": "TCP", "port": p}
                                for p in (8080, 8443, 8444)
                            ],
                        },
                    ],
                },
            )
        )
    return [
        *extra,
        resource(
            profile,
            "rbac.authorization.k8s.io/v1",
            "ClusterRole",
            prefix,
            rules=global_rules,
        ),
        resource(
            profile,
            "rbac.authorization.k8s.io/v1",
            "ClusterRoleBinding",
            prefix,
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": prefix,
            },
            subjects=[subject],
        ),
        resource(
            profile,
            "v1",
            "ServiceAccount",
            "fixture-installer",
            ns,
            automountServiceAccountToken=False,
        ),
        resource(
            profile,
            "coordination.k8s.io/v1",
            "Lease",
            "fixture-installer",
            ns,
            spec={"leaseDurationSeconds": 45},
        ),
        resource(
            profile, "rbac.authorization.k8s.io/v1", "Role", prefix, ns, rules=rules
        ),
        resource(
            profile,
            "rbac.authorization.k8s.io/v1",
            "RoleBinding",
            prefix,
            ns,
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": prefix,
            },
            subjects=[subject],
        ),
        policy,
        binding,
    ]
