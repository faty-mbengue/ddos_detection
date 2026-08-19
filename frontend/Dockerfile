# ── Etape 1 : construction du bundle Vite ────────────────────────────────────
FROM node:22-alpine AS build

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci 2>/dev/null || npm install

COPY . .

# En production, nginx relaie /api et /ws : les URLs restent relatives.
ENV VITE_API_URL=/api \
    VITE_WS_URL=/ws
RUN npm run build

# ── Etape 2 : service statique par nginx ─────────────────────────────────────
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

# 127.0.0.1 explicitement : nginx n'ecoute qu'en IPv4, or "localhost" resout
# d'abord en ::1 dans le conteneur.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1

CMD ["nginx", "-g", "daemon off;"]
