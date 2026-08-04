#!/bin/sh
# Generate a self-signed cert on first start if none is mounted/persisted.
set -e
CERT_DIR=/etc/nginx/certs
if [ ! -f "$CERT_DIR/firefly.crt" ]; then
  echo "No TLS cert found; generating self-signed certificate."
  mkdir -p "$CERT_DIR"
  apk add --no-cache openssl >/dev/null 2>&1 || true
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$CERT_DIR/firefly.key" -out "$CERT_DIR/firefly.crt" \
    -subj "/C=CA/O=WAS705/CN=172.16.24.73"
  echo "Self-signed certificate generated."
fi
