# SPDX-License-Identifier: Apache-2.0
# Reuse the reviewed image; no package downloads or new runtime dependencies.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY runtime/provider_contract.py /opt/service-request/provider_contract.py
COPY runtime/provider-contract.json /opt/service-request/provider-contract.json
COPY src/client.py /opt/service-request/client.py
COPY src/inference.py /opt/service-request/inference.py
COPY src/agent_loop.py /opt/service-request/agent_loop.py
COPY src/remediation.json /opt/service-request/remediation.json
ENTRYPOINT ["python", "/opt/service-request/client.py"]
