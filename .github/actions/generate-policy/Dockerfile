FROM python:3.12-slim

ARG GH_VERSION=2.74.1
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git curl jq mtools zstd xz-utils ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" \
      | tar -xz --strip-components=1 -C /usr/local gh_${GH_VERSION}_linux_amd64/bin/gh

RUN pip install --no-cache-dir pyyaml

ARG CVM_MEASURE_REPO=https://github.com/cohere-ai/cvm-measure.git
ARG CVM_MEASURE_REF=alhassankhedr/cc-167-tdx-measurement-toolkit

RUN git clone --depth 1 --branch "${CVM_MEASURE_REF}" "${CVM_MEASURE_REPO}" /tmp/cvm-measure && \
    pip install --no-cache-dir /tmp/cvm-measure && \
    rm -rf /tmp/cvm-measure

ARG ORAS_VERSION=1.2.0
RUN curl -fSL "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin oras

WORKDIR /app
COPY attestation-policy/ attestation-policy/
COPY generate_policy/ generate_policy/

ENTRYPOINT ["python3", "-m", "generate_policy"]
