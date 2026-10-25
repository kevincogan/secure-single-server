# SPDX-License-Identifier: Apache-2.0
ARG PYTHON_BASE
FROM ${PYTHON_BASE}
ARG PYTHON_RPMS
ARG RPM_MANIFEST_SHA256
ARG SOURCE_MANIFEST_SHA256
USER 0
RUN microdnf install -y --nodocs --setopt=install_weak_deps=0 ${PYTHON_RPMS} && \
    microdnf clean all && \
    rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | LC_ALL=C sort > /usr/share/runtime-rpms.txt && \
    echo "${RPM_MANIFEST_SHA256}  /usr/share/runtime-rpms.txt" | sha256sum -c -
WORKDIR /app
COPY source/ /app/
RUN echo "${SOURCE_MANIFEST_SHA256}  export-manifest.json" | sha256sum -c - && \
    python3.12 -m pip install --no-cache-dir --no-deps -r tests/identity_demo/requirements-lock.txt PyYAML==6.0.3
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/scripts/identity_demo:/app/tests/identity_demo HOME=/state/private
RUN python3.12 scripts/verify-source.py --inventory && \
    python3.12 scripts/check-public-safety.py && \
    python3.12 -m installer_tools > /usr/share/installer-tools.json && \
    chmod -R a+rX /app
LABEL identity-demo.source-manifest-sha256="${SOURCE_MANIFEST_SHA256}"
USER 1001
ENTRYPOINT ["python3.12", "/app/scripts/identity_demo/identity_demo_setup.py"]
