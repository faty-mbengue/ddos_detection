# ── Backend DDoS Monitor — FastAPI + uv ──────────────────────────────────────
FROM python:3.12-slim AS base

# uv est copie depuis son image officielle (pas de pip install)
COPY --from=ghcr.io/astral-sh/uv:0.10.2 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

# tshark permet la capture reelle (CAPTURE_BACKEND=tshark) ; curl sert au healthcheck.
# libcap2-bin fournit setcap, utilise juste apres.
# iptables applique le blocage d'IP (FIREWALL_BACKEND=iptables) : sans lui, la
# liste des IP bloquees resterait un simple inventaire sans effet reseau.
#
# Le paquet Debian pose une question debconf sur l'autorisation de capture par
# les non-root : on y repond a l'avance pour que la construction reste
# entierement automatique.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl \
        tshark \
        tcpdump \
        libcap2-bin \
        iptables \
    && rm -rf /var/lib/apt/lists/*

# Le conteneur tourne sans privileges (voir USER plus bas), or capturer exige
# CAP_NET_RAW. On accorde donc les capabilities au seul binaire qui en a besoin
# — dumpcap, le collecteur appele par tshark — plutot que de passer root.
# Elles ne prennent effet que si Docker les accorde au conteneur
# (cap_add: NET_ADMIN, NET_RAW dans docker-compose.capture.yml).
RUN groupadd --system wireshark \
    && chgrp wireshark /usr/bin/dumpcap \
    && chmod 754 /usr/bin/dumpcap \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap

# Meme principe pour le blocage d'IP : iptables exige CAP_NET_ADMIN, que
# l'utilisateur non privilegie n'a pas dans son jeu effectif. On accorde la
# capability au binaire reel (xtables-nft-multi, vers lequel pointe iptables)
# plutot que d'executer tout le backend en root.
RUN setcap cap_net_admin,cap_net_raw+eip /usr/sbin/xtables-nft-multi

WORKDIR /app

# Couche de dependances mise en cache independamment du code applicatif
COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen --no-install-project --no-dev 2>/dev/null \
    || uv sync --no-install-project --no-dev

COPY app ./app

# Le modele de demonstration est genere a la construction : le conteneur demarre
# immediatement operationnel, meme sans artefacts fournis.
RUN python -m app.ml.train_demo_model

# Execution sans privileges. L'appartenance au groupe wireshark autorise
# l'utilisateur a executer dumpcap, donc a capturer sans etre root.
RUN useradd --create-home --uid 10001 appuser \
    && usermod --append --groups wireshark appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
