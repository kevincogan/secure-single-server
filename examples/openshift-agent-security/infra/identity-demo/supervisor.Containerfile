# SPDX-License-Identifier: Apache-2.0
# /openshell-supervisor must match the native Pod command, including its slash.
FROM ghcr.io/nvidia/openshell/supervisor@sha256:4ab2b970cdb02c7518ba4ccbbadb4861ae9a8d0b8770e5b160697f0453b0a8e4
COPY --chmod=0555 openshell-supervisor /openshell-supervisor
COPY --chmod=0444 libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
COPY --chmod=0444 native-public-trust.pem /etc/ssl/certs/ca-certificates.crt
ARG NATIVE_CONTRACT_SHA256
ARG NATIVE_CA_SHA256
ARG PATCHSET_SHA256
LABEL org.opencontainers.image.revision="e1f3c82caa3ed3b65de22889ae7ef32a774878ef" \
      org.opencontainers.image.version="0.1.3-identity-evaluation" \
      identity-demo.native-contract-sha256="${NATIVE_CONTRACT_SHA256}" \
      identity-demo.native-ca-sha256="${NATIVE_CA_SHA256}" \
      identity-demo.patchset-sha256="${PATCHSET_SHA256}"
USER 1000:1000
