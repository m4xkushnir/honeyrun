FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-setuptools python3-wheel python3-venv \
      strace git curl wget ca-certificates netcat-openbsd tini openssl faketime python3-requests \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 1001 --shell /bin/bash runner

# Libraries real payloads lean on. Without them a stealer crashes on import before it acts,
# and the run looks clean. They sit on NODE_PATH / the system site-packages, like on a dev box.
RUN npm install -g --no-audit --no-fund axios@1 node-fetch@2 request@2 form-data@4 ws@8 >/dev/null 2>&1

COPY agent.py /opt/honeyrun/agent.py
ENTRYPOINT ["/usr/bin/tini", "--", "python3", "/opt/honeyrun/agent.py"]
