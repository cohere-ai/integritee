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
ARG CVM_MEASURE_REF=160e32e60ef2309adba06de41bfaa56f74e8c080

RUN git init /tmp/cvm-measure && \
    git -C /tmp/cvm-measure remote add origin "${CVM_MEASURE_REPO}" && \
    git -C /tmp/cvm-measure fetch --depth 1 origin "${CVM_MEASURE_REF}" && \
    git -C /tmp/cvm-measure checkout --detach FETCH_HEAD && \
    test "$(git -C /tmp/cvm-measure rev-parse HEAD)" = "${CVM_MEASURE_REF}" && \
    pip install --no-cache-dir /tmp/cvm-measure && \
    rm -rf /tmp/cvm-measure

ARG ORAS_VERSION=1.2.0
RUN curl -fSL "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin oras

WORKDIR /app
COPY generate_policy/ generate_policy/
ENV PYTHONPATH=/app

ENTRYPOINT ["python3", "-m", "generate_policy"]
