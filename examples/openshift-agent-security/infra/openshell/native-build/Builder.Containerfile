# SPDX-License-Identifier: Apache-2.0
ARG BUILDER_BASE
FROM ${BUILDER_BASE}
ARG DEBIAN_SNAPSHOT
# A dated signed package repository makes compiler dependencies repeatable.
# Only historical Release freshness is exempted; signature and TLS checks stay on.
RUN test -n "${DEBIAN_SNAPSHOT}" && \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources && \
    printf 'Types: deb\nURIs: https://snapshot.debian.org/archive/debian/%s/\nSuites: trixie\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list.d/identity-build.sources && \
    dpkg --add-architecture amd64 && \
    apt-get update && \
    apt-get install -y --no-install-recommends clang libclang-dev cmake \
      pkg-config g++-x86-64-linux-gnu libz3-dev:amd64 && \
    rustup target add x86_64-unknown-linux-gnu && \
    dpkg-query -W > /usr/local/share/identity-build-packages.txt && \
    rm -rf /var/lib/apt/lists/*
# Match upstream rust-toolchain.toml before the read-only/offline stages.
RUN rustup component add rustfmt rust-src rust-analyzer
ARG CARGO_AUDITABLE_VERSION
RUN test -n "${CARGO_AUDITABLE_VERSION}" && \
    cargo install --locked --version "${CARGO_AUDITABLE_VERSION}" \
      --root /opt/identity-build-tools cargo-auditable
COPY --chmod=0555 build-native.sh /usr/local/bin/build-native
ENV CARGO_HOME=/cache CARGO_TARGET_DIR=/work/output/target \
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
    CXX_x86_64_unknown_linux_gnu=x86_64-linux-gnu-g++ \
    AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    Z3_SYS_Z3_HEADER=/usr/include/z3.h \
    BINDGEN_EXTRA_CLANG_ARGS="--sysroot=/ -I/usr/include/x86_64-linux-gnu"
ENV PATH="/opt/identity-build-tools/bin:${PATH}"
WORKDIR /work/source
ENTRYPOINT ["/usr/local/bin/build-native"]
