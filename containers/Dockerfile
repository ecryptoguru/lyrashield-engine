# ---------------------------------------------------------------------------
# Builder stage: compile the Go tools here so the Go toolchain (~225MB) and the
# module/build caches never reach the runtime image. The resulting binaries are
# statically linked and copied into the final stage.
# ---------------------------------------------------------------------------
# The manifest-list digest is pinned so amd64 and arm64 select the exact base
# image tested by the release workflow. Refresh it only through the sandbox
# release process, never by rebuilding against a moving tag.
FROM kalilinux/kali-rolling@sha256:f49124869e4eee549315879c3bd7ef92f23b8753fec7544537bcec1493277096 AS gobuilder

ARG KALI_APT_SUITE=kali-last-snapshot
ARG KALI_APT_INRELEASE_SHA256=6e298f996675e302bd5465a826ebd246f15b6ebcf71c2839287840be1b4277ee
# The pinned InRelease hash and its APT signature authenticate this immutable
# archive snapshot; the base image predates the archive's current TLS chain.
RUN printf 'deb http://archive.kali.org/kali %s main contrib non-free non-free-firmware\n' "$KALI_APT_SUITE" > /etc/apt/sources.list && \
    printf 'Package: *\nPin: release n=%s\nPin-Priority: 1001\n' "$KALI_APT_SUITE" > /etc/apt/preferences.d/kali-snapshot && \
    rm -f /etc/apt/sources.list.d/* && \
    apt-get update && \
    echo "${KALI_APT_INRELEASE_SHA256}  /var/lib/apt/lists/archive.kali.org_kali_dists_${KALI_APT_SUITE}_InRelease" | sha256sum -c - && \
    apt-get full-upgrade -y && \
    apt-get install -y kali-archive-keyring && \
    apt-get update && \
    apt-get install -y --no-install-recommends golang-go git ca-certificates

ENV GOBIN=/out/bin
ARG HTTPX_COMMIT=811409809ea2b1706c49452149ab454861543138
ARG KATANA_COMMIT=e82a2b803d9a9703b614fae492f648cca926b15b
ARG CVEMAP_COMMIT=08c124da690a5c6acba802998931be13d6ca78ba
ARG GOSPIDER_COMMIT=f6cc9a78d709e088e55ce62e5e92ab063f1a184b
ARG INTERACTSH_COMMIT=810180a230fe2265385ed45695a6635b5026452a
RUN mkdir -p /out/bin && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_COMMIT} && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@${KATANA_COMMIT} && \
    go install -v github.com/projectdiscovery/cvemap/cmd/vulnx@${CVEMAP_COMMIT} && \
    go install -v github.com/jaeles-project/gospider@${GOSPIDER_COMMIT} && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@${INTERACTSH_COMMIT}

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM kalilinux/kali-rolling@sha256:f49124869e4eee549315879c3bd7ef92f23b8753fec7544537bcec1493277096

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

ARG KALI_APT_SUITE=kali-last-snapshot
ARG KALI_APT_INRELEASE_SHA256=6e298f996675e302bd5465a826ebd246f15b6ebcf71c2839287840be1b4277ee
RUN printf 'deb http://archive.kali.org/kali %s main contrib non-free non-free-firmware\n' "$KALI_APT_SUITE" > /etc/apt/sources.list && \
    printf 'Package: *\nPin: release n=%s\nPin-Priority: 1001\n' "$KALI_APT_SUITE" > /etc/apt/preferences.d/kali-snapshot && \
    rm -f /etc/apt/sources.list.d/* && \
    apt-get update && \
    echo "${KALI_APT_INRELEASE_SHA256}  /var/lib/apt/lists/archive.kali.org_kali_dists_${KALI_APT_SUITE}_InRelease" | sha256sum -c - && \
    apt-get full-upgrade -y && \
    apt-get install -y kali-archive-keyring sudo && \
    apt-get update

RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    touch /home/pentester/.hushlogin

RUN mkdir -p /home/pentester/tools /app/certs && \
    chown -R pentester:pentester /app/certs /home/pentester/tools

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    software-properties-common \
    gcc libc6-dev \
    python3 python3-pip python3-venv python3-setuptools \
    net-tools dnsutils whois \
    file xxd \
    jq parallel ripgrep grep \
    less procps htop \
    iproute2 iputils-ping netcat-traditional \
    nmap ncat ndiff \
    sqlmap nuclei subfinder naabu ffuf \
    nodejs npm pipx \
    libcap2-bin \
    gdb \
    libnss3-tools \
    chromium fonts-liberation


USER pentester
RUN openssl ecparam -name prime256v1 -genkey -noout -out /app/certs/ca.key && \
    openssl req -x509 -new -key /app/certs/ca.key \
    -out /app/certs/ca.crt \
    -days 3650 \
    -subj "/C=US/ST=CA/O=Security Testing/CN=Testing Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" && \
    openssl pkcs12 -export \
    -out /app/certs/ca.p12 \
    -inkey /app/certs/ca.key \
    -in /app/certs/ca.crt \
    -passout pass:"" \
    -name "Testing Root CA" && \
    chmod 644 /app/certs/ca.crt && \
    chmod 600 /app/certs/ca.key && \
    chmod 600 /app/certs/ca.p12

USER root
RUN cp /app/certs/ca.crt /usr/local/share/ca-certificates/ca.crt && \
    update-ca-certificates

USER pentester
WORKDIR /tmp

# Go tools are built in the gobuilder stage; copy the static binaries only.
COPY --from=gobuilder --chown=pentester:pentester /out/bin/ /home/pentester/go/bin/

ARG NUCLEI_TEMPLATES_COMMIT=166dcb625c297785f461a567e73885e8c1ae5cf3
RUN mkdir -p /home/pentester/.local && \
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /home/pentester/.local/nuclei-templates && \
    git -C /home/pentester/.local/nuclei-templates fetch --depth 1 origin "${NUCLEI_TEMPLATES_COMMIT}" && \
    git -C /home/pentester/.local/nuclei-templates checkout --detach "${NUCLEI_TEMPLATES_COMMIT}"

COPY --chown=pentester:pentester containers/npm-tools/package.json containers/npm-tools/package-lock.json /home/pentester/.npm-tools/
RUN npm ci --omit=dev --prefix /home/pentester/.npm-tools && \
    npm cache clean --force && \
    # ast-grep ships two identical binaries (`ast-grep` and `sg`); dedupe (~52MB)
    ln -sf ast-grep /home/pentester/.npm-tools/node_modules/@ast-grep/cli/sg

ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV AGENT_BROWSER_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
ENV AGENT_BROWSER_ARGS="--disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--lang=en-US"
ENV AGENT_BROWSER_SCREENSHOT_DIR=/workspace/.agent-browser-screenshots
RUN /home/pentester/.npm-tools/node_modules/.bin/agent-browser doctor --offline --quick

ARG TREE_SITTER_JAVA_COMMIT=e10607b45ff745f5f876bfa3e94fbcc6b44bdc11
ARG TREE_SITTER_JAVASCRIPT_COMMIT=58404d8cf191d69f2674a8fd507bd5776f46cb11
ARG TREE_SITTER_PYTHON_COMMIT=26855eabccb19c6abf499fbc5b8dc7cc9ab8bc64
ARG TREE_SITTER_GO_COMMIT=2346a3ab1bb3857b48b29d779a1ef9799a248cd7
ARG TREE_SITTER_BASH_COMMIT=a06c2e4415e9bc0346c6b86d401879ffb44058f7
ARG TREE_SITTER_JSON_COMMIT=001c28d7a29832b06b0e831ec77845553c89b56d
ARG TREE_SITTER_YAML_COMMIT=a1c4812a73ec5e089de8e441fdea3a921e8d5079
ARG TREE_SITTER_TYPESCRIPT_COMMIT=75b3874edb2dc714fb1fd77a32013d0f8699989f
RUN set -eux; \
    TS_PARSER_DIR="/home/pentester/.tree-sitter/parsers"; \
    mkdir -p "${TS_PARSER_DIR}"; \
    git clone --depth 1 https://github.com/tree-sitter/tree-sitter-java.git "${TS_PARSER_DIR}/tree-sitter-java" && git -C "${TS_PARSER_DIR}/tree-sitter-java" fetch --depth 1 origin "${TREE_SITTER_JAVA_COMMIT}" && git -C "${TS_PARSER_DIR}/tree-sitter-java" checkout --detach "${TREE_SITTER_JAVA_COMMIT}"; \
    git clone --depth 1 https://github.com/tree-sitter/tree-sitter-javascript.git "${TS_PARSER_DIR}/tree-sitter-javascript" && git -C "${TS_PARSER_DIR}/tree-sitter-javascript" fetch --depth 1 origin "${TREE_SITTER_JAVASCRIPT_COMMIT}" && git -C "${TS_PARSER_DIR}/tree-sitter-javascript" checkout --detach "${TREE_SITTER_JAVASCRIPT_COMMIT}"; \
    git clone --depth 1 https://github.com/tree-sitter/tree-sitter-python.git "${TS_PARSER_DIR}/tree-sitter-python" && git -C "${TS_PARSER_DIR}/tree-sitter-python" fetch --depth 1 origin "${TREE_SITTER_PYTHON_COMMIT}" && git -C "${TS_PARSER_DIR}/tree-sitter-python" checkout --detach "${TREE_SITTER_PYTHON_COMMIT}"; \
    git clone --depth 1 https://github.com/tree-sitter/tree-sitter-go.git "${TS_PARSER_DIR}/tree-sitter-go" && git -C "${TS_PARSER_DIR}/tree-sitter-go" fetch --depth 1 origin "${TREE_SITTER_GO_COMMIT}" && git -C "${TS_PARSER_DIR}/tree-sitter-go" checkout --detach "${TREE_SITTER_GO_COMMIT}"; \
    git clone --depth 1 https://github.com/tree-sitter/tree-sitter-bash.git "${TS_PARSER_DIR}/tree-sitter-bash" && git -C "${TS_PARSER_DIR}/tree-sitter-bash" fetch --depth 1 origin "${TREE_SITTER_BASH_COMMIT}" && git -C "${TS_PARSER_DIR}/tree-sitter-bash" checkout --detach "${TREE_SITTER_BASH_COMMIT}"; \
    git clone --depth 1 https://github.com/tree-sitter/tree-sitter-json.git "${TS_PARSER_DIR}/tree-sitter-json" && git -C "${TS_PARSER_DIR}/tree-sitter-json" fetch --depth 1 origin "${TREE_SITTER_JSON_COMMIT}" && git -C "${TS_PARSER_DIR}/tree-sitter-json" checkout --detach "${TREE_SITTER_JSON_COMMIT}"; \
    git clone --depth 1 https://github.com/tree-sitter-grammars/tree-sitter-yaml.git "${TS_PARSER_DIR}/tree-sitter-yaml" && git -C "${TS_PARSER_DIR}/tree-sitter-yaml" fetch --depth 1 origin "${TREE_SITTER_YAML_COMMIT}" && git -C "${TS_PARSER_DIR}/tree-sitter-yaml" checkout --detach "${TREE_SITTER_YAML_COMMIT}"; \
    git clone --depth 1 https://github.com/tree-sitter/tree-sitter-typescript.git "${TS_PARSER_DIR}/tree-sitter-typescript" && git -C "${TS_PARSER_DIR}/tree-sitter-typescript" fetch --depth 1 origin "${TREE_SITTER_TYPESCRIPT_COMMIT}" && git -C "${TS_PARSER_DIR}/tree-sitter-typescript" checkout --detach "${TREE_SITTER_TYPESCRIPT_COMMIT}"; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" "${TS_PARSER_DIR}/tree-sitter-typescript-typescript"; \
    fi; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" "${TS_PARSER_DIR}/tree-sitter-typescript-tsx"; \
    fi; \
    tree-sitter init-config >/dev/null 2>&1 || true; \
    TS_CONFIG="/home/pentester/.config/tree-sitter/config.json"; \
    mkdir -p "$(dirname "${TS_CONFIG}")"; \
    [ -f "${TS_CONFIG}" ] || printf '{}\n' > "${TS_CONFIG}"; \
    TMP_CFG="$(mktemp)"; \
    jq --arg p "${TS_PARSER_DIR}" '.["parser-directories"] = ((.["parser-directories"] // []) + [$p] | unique)' "${TS_CONFIG}" > "${TMP_CFG}"; \
    mv "${TMP_CFG}" "${TS_CONFIG}"

WORKDIR /home/pentester/tools
ARG JS_SNOOPER_COMMIT=932704cbce1a04ebe89a558f395a6e474e01b15b
ARG JSNIPER_COMMIT=65d0b508dc88e6de3dfe6ac60e6d89eca22be686
ARG JWT_TOOL_COMMIT=3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b
RUN git clone --depth 1 https://github.com/aravind0x7/JS-Snooper.git && \
    git -C JS-Snooper fetch --depth 1 origin "${JS_SNOOPER_COMMIT}" && \
    git -C JS-Snooper checkout --detach "${JS_SNOOPER_COMMIT}" && \
    chmod +x JS-Snooper/js_snooper.sh && \
    git clone --depth 1 https://github.com/xchopath/jsniper.sh.git && \
    git -C jsniper.sh fetch --depth 1 origin "${JSNIPER_COMMIT}" && \
    git -C jsniper.sh checkout --detach "${JSNIPER_COMMIT}" && \
    chmod +x jsniper.sh/jsniper.sh && \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git && \
    git -C jwt_tool fetch --depth 1 origin "${JWT_TOOL_COMMIT}" && \
    git -C jwt_tool checkout --detach "${JWT_TOOL_COMMIT}" && \
    chmod +x jwt_tool/jwt_tool.py

USER root

ARG TRUFFLEHOG_VERSION=3.96.0
ARG TRUFFLEHOG_LINUX_X64_SHA256=7105f1cd6577f058a9e39d0578f1a99c8a1e481e4d3512cd8a09acfe22a0fdc0
ARG TRUFFLEHOG_LINUX_ARM64_SHA256=50acd4c7a3b8ebfe5083d8350956057030c44be3515dedd55b45263495c490b2
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) TRUFFLEHOG_ARCH="amd64"; TRUFFLEHOG_SHA256="$TRUFFLEHOG_LINUX_X64_SHA256" ;; \
        aarch64|arm64) TRUFFLEHOG_ARCH="arm64"; TRUFFLEHOG_SHA256="$TRUFFLEHOG_LINUX_ARM64_SHA256" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TRUFFLEHOG_ARCH}.tar.gz" -o /tmp/trufflehog.tgz; \
    echo "${TRUFFLEHOG_SHA256}  /tmp/trufflehog.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trufflehog.tgz -C /tmp; \
    install -m 0755 /tmp/trufflehog /usr/local/bin/trufflehog; \
    rm -f /tmp/trufflehog /tmp/trufflehog.tgz
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_LINUX_X64_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_LINUX_ARM64_SHA256=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) GITLEAKS_ARCH="x64"; GITLEAKS_SHA256="$GITLEAKS_LINUX_X64_SHA256" ;; \
        aarch64|arm64) GITLEAKS_ARCH="arm64"; GITLEAKS_SHA256="$GITLEAKS_LINUX_ARM64_SHA256" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" -o /tmp/gitleaks.tgz; \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tgz -C /tmp; \
    install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks; \
    rm -f /tmp/gitleaks /tmp/gitleaks.tgz

ARG TRIVY_VERSION=0.73.0
ARG TRIVY_LINUX_X64_SHA256=2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b
ARG TRIVY_LINUX_ARM64_SHA256=13833d97e8a1a5367471c372a173180157f593bece570e20d5d925fef552f5dd
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) TRIVY_ARCH="64bit"; TRIVY_SHA256="$TRIVY_LINUX_X64_SHA256" ;; \
        aarch64|arm64) TRIVY_ARCH="ARM64"; TRIVY_SHA256="$TRIVY_LINUX_ARM64_SHA256" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" -o /tmp/trivy.tgz; \
    echo "${TRIVY_SHA256}  /tmp/trivy.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tgz -C /tmp; \
    install -m 0755 /tmp/trivy /usr/local/bin/trivy; \
    rm -f /tmp/trivy /tmp/trivy.tgz

RUN apt-get update && \
    apt-get install -y --no-install-recommends wapiti

USER pentester

USER root

RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    # Purge non-English locales (~160MB)
    find /usr/share/locale -mindepth 1 -maxdepth 1 -type d \
        ! -name 'en' ! -name 'en_US' ! -name 'C' -exec rm -rf {} + && \
    # Remove package documentation and man pages not needed at runtime (~95MB)
    rm -rf /usr/share/doc/* /usr/share/doc-base/* /usr/share/man/*

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-tools/node_modules/.bin:/app/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/.venv"

WORKDIR /app

ARG CAIDO_VERSION=0.56.0
ARG CAIDO_LINUX_X64_SHA256=1bc13f1ad558cd333924890d9d09b73f1cdf6726b7855265cd4c4ddece0211d3
ARG CAIDO_LINUX_ARM64_SHA256=5fe8c37ac0435ce5924014cf035902686051be86831824744e435636a62d3689
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) CAIDO_ARCH="x86_64"; CAIDO_SHA256="$CAIDO_LINUX_X64_SHA256" ;; \
        aarch64|arm64) CAIDO_ARCH="aarch64"; CAIDO_SHA256="$CAIDO_LINUX_ARM64_SHA256" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz" -o /tmp/caido-cli.tgz; \
    echo "${CAIDO_SHA256}  /tmp/caido-cli.tgz" | sha256sum -c -; \
    tar -xzf /tmp/caido-cli.tgz -C /tmp; \
    install -m 0755 /tmp/caido-cli /usr/local/bin/caido-cli; \
    rm -f /tmp/caido-cli /tmp/caido-cli.tgz

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

COPY --chown=pentester:pentester containers/python-requirements.txt /tmp/python-requirements.txt

USER pentester
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir --require-hashes -r /tmp/python-requirements.txt && \
    printf '%s\n' \
        '#!/bin/bash' \
        'exec /app/.venv/bin/python /home/pentester/tools/jwt_tool/jwt_tool.py "$@"' \
        > /home/pentester/.local/bin/jwt_tool && \
    chmod +x /home/pentester/.local/bin/jwt_tool

COPY --chown=pentester:pentester strix/tools/proxy/caido_api.py /opt/strix-python/caido_api.py
ENV PYTHONPATH=/opt/strix-python

# Login shells (e.g. `bash -lc`) source /etc/profile, which on Debian/Kali
# hard-resets PATH and drops the image's ENV PATH entries. Re-add the same
# directories here — including /app/.venv/bin — so `python3`/`pip` resolve to
# the venv (which ships requests, httpx, bs4, lxml, pyjwt, cryptography, and the
# Caido SDK) instead of the externally-managed system interpreter.
RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-tools/node_modules/.bin:/app/.venv/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-tools/node_modules/.bin:/app/.venv/bin:$PATH"' >> /home/pentester/.profile

USER root
RUN setcap cap_net_raw,cap_net_bind_service+eip /usr/lib/nmap/nmap
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
