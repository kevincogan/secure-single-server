#!/usr/bin/env bash
set -euo pipefail

DEMO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="openshell-streamlit-demo:unsafe"

: "${OPENAI_API_KEY:?export OPENAI_API_KEY before running the unsafe demo}"
: "${STREAMLIT_DEMO_PROVIDER:?export STREAMLIT_DEMO_PROVIDER, for example streamlit-demo-openai}"
: "${MODEL_BASE_URL:?export MODEL_BASE_URL, for example https://api.openai.com/v1}"
: "${OPENAI_MODEL:?export OPENAI_MODEL, for example gpt-5.5}"

cd "${DEMO_DIR}"
podman build -t "${IMAGE}" .
podman run --rm -p 127.0.0.1:8501:8501 \
  --env DEMO_MODE=unsafe \
  --env STREAMLIT_DEMO_PROVIDER \
  --env OPENAI_API_KEY \
  --env MODEL_BASE_URL \
  --env OPENAI_MODEL \
  --env DEMO_MARKER=demo-not-a-real-secret \
  "${IMAGE}"
