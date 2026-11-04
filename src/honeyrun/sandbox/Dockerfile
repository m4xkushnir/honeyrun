FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-setuptools python3-wheel python3-venv \
      strace git curl wget ca-certificates netcat-openbsd tini openssl faketime python3-requests bind9-dnsutils \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 1001 --shell /bin/bash runner

# Libraries real payloads lean on. Without them a stealer crashes on import before it acts,
# and the run looks clean. They sit on NODE_PATH / the system site-packages, like on a dev box.
RUN npm install -g --no-audit --no-fund axios@1 node-fetch@2 request@2 form-data@4 ws@8 >/dev/null 2>&1
# Build backends and libraries common on a dev box: without them most sdists fail to build
# before setup code runs, and image-handling payloads crash on import.
RUN pip install --no-cache-dir --break-system-packages \
      "hatchling==1.27.0" "poetry-core==2.1.3" "flit-core==3.12.0" "pdm-backend==2.4.5" \
      "setuptools-scm==8.3.1" "pillow==11.2.1" >/dev/null 2>&1

COPY agent.py /opt/honeyrun/agent.py
ENTRYPOINT ["/usr/bin/tini", "--", "python3", "/opt/honeyrun/agent.py"]
