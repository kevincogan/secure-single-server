# SPDX-License-Identifier: Apache-2.0
# Context contains only reviewed AMD64 binary/libraries and public trust.
FROM ghcr.io/nvidia/openshell/gateway@sha256:ea14aa4db0980fab4769fb6b5509ac42ae3dc8495e645b1ba1fe1ada49892fa6
COPY --chmod=0555 openshell-gateway /usr/local/bin/openshell-gateway
COPY --chmod=0444 libz3.so.4 /usr/lib/x86_64-linux-gnu/libz3.so.4
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
