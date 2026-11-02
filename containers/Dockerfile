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
# Supply-chain anchor for the Kali apt index. `kali-last-snapshot` is a
# re-signed rolling pointer, so its InRelease bytes change on every archive
# refresh and cannot be pinned durably. The trust anchor is instead the pinned
# base image's own Kali keyring, whose content hash is fixed by the
# digest-pinned FROM above; the apt signature verification that keyring
# performs is enforced fail-closed in the RUN below. The `deb` line names that
# same keyring with `signed-by`, so the file the hash check below pins is
# exactly the file apt trusts to authenticate the index; without it apt would
# fall back to whatever trusted key is present in the image.
ARG KALI_APT_KEYRING_SHA256=42a247ff5a26869e3739b6d3ad125938bb5da8e7bb43ed0791d2a190cd09c64f
RUN printf 'deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://archive.kali.org/kali %s main contrib non-free non-free-firmware\n' "$KALI_APT_SUITE" > /etc/apt/sources.list && \
    printf 'Package: *\nPin: release n=%s\nPin-Priority: 1001\n' "$KALI_APT_SUITE" > /etc/apt/preferences.d/kali-snapshot && \
    rm -f /etc/apt/sources.list.d/* && \
    printf 'APT::Get::AllowUnauthenticated "false";\nAcquire::AllowInsecureRepositories "false";\nAcquire::AllowDowngradeToInsecureRepositories "false";\n' > /etc/apt/apt.conf.d/99lyrashield-signature-required && \
    echo "${KALI_APT_KEYRING_SHA256}  /usr/share/keyrings/kali-archive-keyring.gpg" | sha256sum -c - && \
    apt-get update && \
    apt-get full-upgrade -y --allow-downgrades && \
    apt-get install -y kali-archive-keyring && \
    apt-get update && \
    apt-get install -y --no-install-recommends curl tar git patch ca-certificates

# Official compiler archives are pinned independently of the rolling apt suite.
# GOTOOLCHAIN=local prevents a dependency from downloading a different compiler.
ARG GO_VERSION=1.27.3
ARG GO_LINUX_AMD64_SHA256=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
ARG GO_LINUX_ARM64_SHA256=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
RUN set -eux; \
    case "$(uname -m)" in \
        x86_64) GO_ARCH=amd64; GO_SHA256="$GO_LINUX_AMD64_SHA256" ;; \
        aarch64|arm64) GO_ARCH=arm64; GO_SHA256="$GO_LINUX_ARM64_SHA256" ;; \
        *) echo "Unsupported architecture" >&2; exit 1 ;; \
    esac; \
    curl --retry 5 --retry-delay 2 --retry-max-time 120 -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tgz; \
    echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c -; \
    tar -xzf /tmp/go.tgz -C /usr/local; \
    rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:${PATH}" GOTOOLCHAIN=local GOSUMDB=sum.golang.org
COPY containers/go-tools/ /opt/lyrashield/go-tools/
RUN sh /opt/lyrashield/go-tools/build.sh /out/bin

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM kalilinux/kali-rolling@sha256:f49124869e4eee549315879c3bd7ef92f23b8753fec7544537bcec1493277096

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

ARG KALI_APT_SUITE=kali-last-snapshot
ARG KALI_APT_KEYRING_SHA256=42a247ff5a26869e3739b6d3ad125938bb5da8e7bb43ed0791d2a190cd09c64f
RUN printf 'deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://archive.kali.org/kali %s main contrib non-free non-free-firmware\n' "$KALI_APT_SUITE" > /etc/apt/sources.list && \
    printf 'Package: *\nPin: release n=%s\nPin-Priority: 1001\n' "$KALI_APT_SUITE" > /etc/apt/preferences.d/kali-snapshot && \
    rm -f /etc/apt/sources.list.d/* && \
    printf 'APT::Get::AllowUnauthenticated "false";\nAcquire::AllowInsecureRepositories "false";\nAcquire::AllowDowngradeToInsecureRepositories "false";\n' > /etc/apt/apt.conf.d/99lyrashield-signature-required && \
    echo "${KALI_APT_KEYRING_SHA256}  /usr/share/keyrings/kali-archive-keyring.gpg" | sha256sum -c - && \
    apt-get update && \
    apt-get full-upgrade -y --allow-downgrades && \
    apt-get install -y kali-archive-keyring && \
    apt-get update

# The runtime agent runs as the unprivileged `pentester` user with no sudo
# grant; the entrypoint performs the privileged startup phase as root and then
# irreversibly drops to `pentester` via setpriv before any agent work.
RUN useradd -m -s /bin/bash pentester && \
    touch /home/pentester/.hushlogin

RUN mkdir -p /home/pentester/tools /app/certs && \
    chown -R pentester:pentester /app/certs /home/pentester/tools

COPY containers/distrust_emsign_g3.sh /opt/lyrashield/distrust_emsign_g3.sh

# Bootstrap HTTPS trust through the signed archive, then use Kali's official
# CDN for the large runtime tool set. The suite, pinned keyring, signed-by and
# fail-closed apt signature policy remain identical to the archive bootstrap.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    sh /opt/lyrashield/distrust_emsign_g3.sh && \
    printf 'deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] https://kali.download/kali %s main contrib non-free non-free-firmware\n' "$KALI_APT_SUITE" > /etc/apt/sources.list && \
    apt-get update && \
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
    update-ca-certificates && \
    sh /opt/lyrashield/distrust_emsign_g3.sh

USER pentester
WORKDIR /tmp

COPY containers/verify_go_tools.py /opt/lyrashield/verify_go_tools.py

# Go tools are built in the gobuilder stage; copy the static binaries only.
COPY --from=gobuilder --chown=pentester:pentester /out/bin/ /home/pentester/go/bin/
COPY --from=gobuilder /out/share/go-tools/ /usr/local/share/lyrashield/go-tools/

ARG NUCLEI_TEMPLATES_COMMIT=166dcb625c297785f461a567e73885e8c1ae5cf3
RUN mkdir -p /home/pentester/.local && \
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /home/pentester/.local/nuclei-templates && \
    git -C /home/pentester/.local/nuclei-templates fetch --depth 1 origin "${NUCLEI_TEMPLATES_COMMIT}" && \
    git -C /home/pentester/.local/nuclei-templates checkout --detach "${NUCLEI_TEMPLATES_COMMIT}"

COPY --chown=pentester:pentester containers/npm-tools/package.json containers/npm-tools/package-lock.json /home/pentester/.npm-tools/
COPY --chown=pentester:pentester containers/patch_retire_tls.cjs /tmp/patch_retire_tls.cjs
RUN npm ci --omit=dev --prefix /home/pentester/.npm-tools && \
    node /tmp/patch_retire_tls.cjs /home/pentester/.npm-tools/node_modules && \
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

# Gitleaks, Trivy and TruffleHog are rebuilt from the same pinned release
# sources in gobuilder, with the reviewed security graph. Unpacked executables
# retain Go build metadata so the release image audit can inspect every tool.
RUN install -m 0755 /home/pentester/go/bin/gitleaks /usr/local/bin/gitleaks && \
    install -m 0755 /home/pentester/go/bin/trivy /usr/local/bin/trivy && \
    install -m 0755 /home/pentester/go/bin/trufflehog /usr/local/bin/trufflehog && \
    rm /home/pentester/go/bin/gitleaks /home/pentester/go/bin/trivy /home/pentester/go/bin/trufflehog

RUN apt-get update && \
    apt-get install -y --no-install-recommends wapiti

USER pentester

USER root

# Kali's signed kali-last-snapshot index still serves vulnerable 1.2.0-4+b1.
# Install both Debian decoder packages, checksum-pinned for each CPU. Python's
# extension statically bundles its decoder. Keep this after the final APT install.
COPY containers/install_brotli.sh /opt/lyrashield/install_brotli.sh
RUN sh /opt/lyrashield/install_brotli.sh

RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    # Purge non-English locales (~160MB)
    find /usr/share/locale -mindepth 1 -maxdepth 1 -type d \
        ! -name 'en' ! -name 'en_US' ! -name 'C' -exec rm -rf {} + && \
    # Remove package documentation and man pages not needed at runtime (~95MB)
    rm -rf /usr/share/doc/* /usr/share/doc-base/* /usr/share/man/*

# Apply qualified distro leaves/backports after every APT operation. Keep the
# verifier and provenance available for final non-root, offline image smoke.
COPY containers/system-python-security /opt/lyrashield/system-python-security
RUN /usr/bin/python3 /opt/lyrashield/system-python-security/install_leaves.py \
    --cache /opt/lyrashield/system-python-security/cache && \
    /usr/bin/python3 /opt/lyrashield/system-python-security/amend_sources.py && \
    /usr/bin/python3 /opt/lyrashield/system-python-security/verify_runtime.py

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
    curl --retry 5 --retry-delay 2 --retry-max-time 120 -fsSL "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz" -o /tmp/caido-cli.tgz; \
    echo "${CAIDO_SHA256}  /tmp/caido-cli.tgz" | sha256sum -c -; \
    tar -xzf /tmp/caido-cli.tgz -C /tmp; \
    install -m 0755 /tmp/caido-cli /usr/local/bin/caido-cli; \
    rm -f /tmp/caido-cli /tmp/caido-cli.tgz

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

COPY --chown=pentester:pentester containers/python-requirements.txt /tmp/python-requirements.txt
COPY --chown=pentester:pentester containers/dirsearch-requirements.txt /tmp/dirsearch-requirements.txt
COPY --chown=pentester:pentester containers/patch_dirsearch_metadata.py /tmp/patch_dirsearch_metadata.py
COPY --chown=pentester:pentester containers/repair_pip_vendors.py /tmp/repair_pip_vendors.py
COPY --chown=pentester:pentester containers/pip_vendor_wheels.json /tmp/pip_vendor_wheels.json

USER pentester
# Install the complete audited hash lock without re-resolving Semgrep's narrow
# JWT/MCP/telemetry metadata restrictions; reviewed patches and pip check enforce the graph.
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --force-reinstall --no-cache-dir --no-deps --require-hashes -r /tmp/python-requirements.txt && \
    /app/.venv/bin/python /tmp/repair_pip_vendors.py && \
    /app/.venv/bin/pip install --no-cache-dir --no-deps --require-hashes -r /tmp/dirsearch-requirements.txt && \
    /app/.venv/bin/python /tmp/patch_dirsearch_metadata.py && \
    /app/.venv/bin/python /tmp/patch_dirsearch_metadata.py --package semgrep --runtime-dependencies && \
    /app/.venv/bin/pip check && \
    printf '%s\n' \
        '#!/bin/bash' \
        'exec /app/.venv/bin/python /home/pentester/tools/jwt_tool/jwt_tool.py "$@"' \
        > /home/pentester/.local/bin/jwt_tool && \
    chmod +x /home/pentester/.local/bin/jwt_tool

# Ship the guarded LyraShield proxy helper, not the upstream strix copy: the
# import path documented in the agent prompt (`import caido_api`) must exercise
# the replay egress guard. One implementation lives in
# lyrashield/tools/proxy/caido_api.py; this COPY is its only packaging step.
COPY --chown=root:root lyrashield/runtime/target_relay_proxy.py /opt/lyrashield/target_relay_proxy.py
COPY --chown=root:root containers/verify_semgrep_pyjwt.py /opt/lyrashield/verify_semgrep_pyjwt.py
COPY --chown=root:root containers/verify_brotli.py /opt/lyrashield/verify_brotli.py
COPY --chown=root:root containers/verify_pip_vendors.py /opt/lyrashield/verify_pip_vendors.py
COPY --chown=root:root containers/verify_ca_bundle.py /opt/lyrashield/verify_ca_bundle.py
COPY --chown=root:root lyrashield/tools/proxy/caido_api.py /opt/strix-python/caido_api.py
ENV PYTHONPATH=/opt/strix-python

# Login shells (e.g. `bash -lc`) source /etc/profile, which on Debian/Kali
# hard-resets PATH and drops the image's ENV PATH entries. Re-add the same
# directories here — including /app/.venv/bin — so `python3`/`pip` resolve to
# the venv (which ships requests, httpx, bs4, lxml, pyjwt, cryptography, and the
# Caido SDK) instead of the externally-managed system interpreter.
RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-tools/node_modules/.bin:/app/.venv/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-tools/node_modules/.bin:/app/.venv/bin:$PATH"' >> /home/pentester/.profile

USER root
RUN install -d -m 0700 -o root -g root /run/lyrashield-relay
RUN setcap cap_net_raw,cap_net_bind_service+eip /usr/lib/nmap/nmap
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Start as root: the entrypoint performs the privileged startup phase, then
# irreversibly execs the agent phase as the unprivileged pentester user.
USER root
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
