# SPDX-License-Identifier: Apache-2.0
ARG PYTHON_BASE
FROM ${PYTHON_BASE}
ARG PYTHON_RPMS
ARG RPM_MANIFEST_SHA256
USER 0
RUN microdnf install -y --nodocs --setopt=install_weak_deps=0 ${PYTHON_RPMS} && \
    microdnf clean all && \
    rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | LC_ALL=C sort > /usr/share/runtime-rpms.txt && \
    echo "${RPM_MANIFEST_SHA256}  /usr/share/runtime-rpms.txt" | sha256sum -c -
WORKDIR /app
COPY requirements-lock.txt /app/requirements-lock.txt
RUN python3.12 -m pip install --no-cache-dir --no-deps -r /app/requirements-lock.txt PyYAML==6.0.3
COPY tools/ /usr/local/bin/
COPY scripts/ /app/scripts/
COPY runtime/ /app/runtime/
COPY workloads/ /app/workloads/
COPY infra/ /app/infra/
RUN chmod -R a+rX /app && chmod 0555 /usr/local/bin/oc /usr/local/bin/openshell
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/state/private \
    PYTHONPATH=/app/runtime:/app/runtime/identity_demo:/app/scripts/identity_demo
USER 1001
ENTRYPOINT ["python3.12", "/app/scripts/identity_demo/identity_demo_cluster_bootstrap.py"]
