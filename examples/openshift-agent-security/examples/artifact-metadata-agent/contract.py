# SPDX-License-Identifier: Apache-2.0
"""Host-owned versioned metadata registration contract, using public imports only."""
import re

from agent_security_runtime import ConnectorContract, Denied

CATALOG = re.compile(r'catalog:[a-z][a-z0-9-]{0,31}')
ARTIFACT = re.compile(r'sha256:[0-9a-f]{64}')
TOKEN = re.compile(r'[a-z][a-z0-9-]{0,47}')
OPERATION = re.compile(r'[0-9a-f]{32}')
FIELDS = {'catalog', 'artifact', 'component', 'media_type', 'size_bytes', 'tags'}


def valid_scope(value):
    return isinstance(value, str) and CATALOG.fullmatch(value) is not None


def normalize(value):
    if type(value) is not dict or set(value) not in (FIELDS, FIELDS | {'operation_id'}):
        raise Denied('artifact_metadata_schema')
    if not valid_scope(value['catalog']):
        raise Denied('artifact_catalog_schema')
    if type(value['artifact']) is not str or ARTIFACT.fullmatch(value['artifact']) is None:
        raise Denied('artifact_digest_schema')
    if type(value['component']) is not str or TOKEN.fullmatch(value['component']) is None:
        raise Denied('artifact_component_schema')
    if value['media_type'] != 'application/octet-stream':
        raise Denied('artifact_media_type_schema')
    if type(value['size_bytes']) is not int or not 0 <= value['size_bytes'] <= 1024 ** 3:
        raise Denied('artifact_size_schema')
    tags = value['tags']
    if (type(tags) is not list or not 1 <= len(tags) <= 8
            or any(type(tag) is not str or TOKEN.fullmatch(tag) is None for tag in tags)
            or len(set(tags)) != len(tags)):
        raise Denied('artifact_tags_schema')
    result = dict(value, tags=sorted(tags))
    if 'operation_id' in value:
        if type(value['operation_id']) is not str or OPERATION.fullmatch(value['operation_id']) is None:
            raise Denied('artifact_operation_schema')
    return result


def proposal(value, action):
    if type(value) is not dict or 'operation_id' in value:
        raise Denied('agent_supplied_operation_marker')
    return normalize(dict(normalize(value), operation_id=action))


def check_reference(scope, reference):
    if not valid_scope(scope) or type(reference) is not str:
        raise Denied('artifact_backend_reference')
    if re.fullmatch(re.escape('artifact-meta://' + scope + '/') + r'[0-9a-f]{32}', reference) is None:
        raise Denied('artifact_backend_reference')


CONTRACT = ConnectorContract(
    identifier='artifact-metadata-registration-v1',
    backend='local-artifact-catalog-v1',
    schema='artifact-metadata-v1',
    tool='register_artifact_metadata',
    normalize=normalize,
    resource=lambda value: value['catalog'],
    valid_scope=valid_scope,
    proposal=proposal,
    check_reference=check_reference,
    has_marker=lambda value, operation: value.get('operation_id') == operation,
    user_roles=frozenset({'catalog-curator', 'catalog-observer'}),
    workload_roles=frozenset({'metadata-worker', 'catalog-reader'}),
    write_user_roles=frozenset({'catalog-curator'}),
    write_workload_roles=frozenset({'metadata-worker'}),
    scope_denial='artifact_catalog_permission',
    read_reason='artifact_catalog_read',
)
