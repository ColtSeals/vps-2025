#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/pmesp-api"
REPO_URL="https://github.com/ColtSeals/vps-2025.git"
BRANCH="main"

need_cmd() { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -ne 0 ]; then
  echo "❌ Rode como root (ou use sudo)."
  exit 1
fi

echo "==> Instalando dependências..."
apt update -y >/dev/null
apt install -y git ca-certificates curl openssl >/dev/null

if ! need_cmd docker; then
  echo "==> Instalando Docker..."
  apt install -y docker.io docker-compose >/dev/null
  systemctl enable --now docker
fi

echo "==> Preparando diretório..."
rm -rf "$APP_DIR"
git clone -b "$BRANCH" "$REPO_URL" "$APP_DIR"
cd "$APP_DIR"

echo "==> Garantindo .env com segredos..."
if [ ! -f ".env" ]; then
  echo "❌ .env não existe no repo. Crie e commite."
  exit 1
fi

# Se tiver placeholders, gera segredos e substitui no .env
if grep -q "__CHANGE_ME__" .env; then
  POSTGRES_PASSWORD="$(openssl rand -hex 16)"
  JWT_SECRET="$(openssl rand -hex 32)"
  ADMIN_PASSWORD="$(openssl rand -base64 18)"

  sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${POSTGRES_PASSWORD}/" .env
  sed -i "s/^JWT_SECRET=.*/JWT_SECRET=${JWT_SECRET}/" .env
  sed -i "s/^ADMIN_PASSWORD=.*/ADMIN_PASSWORD=${ADMIN_PASSWORD}/" .env

  echo "✅ Segredos gerados na VPS."
  echo "🔐 ADMIN_PASSWORD=${ADMIN_PASSWORD}"
fi

echo "==> Subindo containers..."
docker compose up -d --build

echo
echo "✅ Pronto!"
echo "➡ API Docs: http://SEU_IP:8000/docs"
echo "➡ Health:   http://127.0.0.1:8000/health"
