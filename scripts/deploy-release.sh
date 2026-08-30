#!/usr/bin/env bash
# Fetch the latest (or a specific) GitHub Release of proxy-panel and (re)deploy
# it locally with Docker Compose. Run this on the VPS whenever you want to
# install or update — nothing on GitHub's side touches your server; you are
# always the one pulling.
#
# Usage:
#   ./deploy-release.sh              # deploy the latest release
#   ./deploy-release.sh v1.2.0       # deploy a specific tag
set -Eeuo pipefail

REPO="maryoa61/proxy-panel"
TAG="${1:-latest}"
DEPLOY_DIR="${DEPLOY_DIR:-$(pwd)}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required." >&2
  exit 1
fi

if [ "$TAG" = "latest" ]; then
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
else
  API_URL="https://api.github.com/repos/${REPO}/releases/tags/${TAG}"
fi

echo "Looking up release: ${TAG}"
RELEASE_JSON="$(curl -fsSL "$API_URL")"
RESOLVED_TAG="$(printf '%s' "$RELEASE_JSON" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
ASSET_URL="$(printf '%s' "$RELEASE_JSON" | grep -o '"browser_download_url": *"[^"]*proxy-panel-[^"]*\.tar\.gz"' | sed -E 's/.*"(https:[^"]+)"/\1/' | head -n1)"
COMPOSE_URL="$(printf '%s' "$RELEASE_JSON" | grep -o '"browser_download_url": *"[^"]*docker-compose.release.yml"' | sed -E 's/.*"(https:[^"]+)"/\1/' | head -n1)"

if [ -z "$ASSET_URL" ]; then
  echo "Could not find an image archive attached to release ${TAG}." >&2
  exit 1
fi

echo "Resolved tag: ${RESOLVED_TAG}"
echo "Downloading image archive..."
curl -fsSL "$ASSET_URL" -o /tmp/proxy-panel-release.tar.gz

echo "Loading image into Docker..."
docker load < /tmp/proxy-panel-release.tar.gz
rm -f /tmp/proxy-panel-release.tar.gz

mkdir -p "$DEPLOY_DIR"
cd "$DEPLOY_DIR"

if [ -n "$COMPOSE_URL" ] && [ ! -f docker-compose.release.yml ]; then
  echo "Fetching docker-compose.release.yml..."
  curl -fsSL "$COMPOSE_URL" -o docker-compose.release.yml
fi

if [ ! -f .env ]; then
  echo
  echo "No .env found in ${DEPLOY_DIR}."
  echo "Create one with at least JWT_SECRET_KEY and ADMIN_PASSWORD before continuing:"
  echo "  JWT_SECRET_KEY=\$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
  echo "  ADMIN_USERNAME=admin"
  echo "  ADMIN_PASSWORD=a-strong-password"
  exit 1
fi

echo "Starting proxy-panel ${RESOLVED_TAG}..."
docker compose -f docker-compose.release.yml up -d
docker image prune -f

echo
echo "Done. proxy-panel ${RESOLVED_TAG} is running."
