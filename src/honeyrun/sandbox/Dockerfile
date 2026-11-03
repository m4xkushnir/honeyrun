FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-setuptools python3-wheel python3-venv \
      strace git curl wget ca-certificates netcat-openbsd tini openssl faketime \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 1001 --shell /bin/bash runner

COPY agent.py /opt/honeyrun/agent.py
ENTRYPOINT ["/usr/bin/tini", "--", "python3", "/opt/honeyrun/agent.py"]
