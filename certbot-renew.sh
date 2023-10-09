#!/usr/bin/env bash

set -euo pipefail

certbot \
  --agree-tos \
  --email "$1" \
  --work-dir "$(pwd)" \
  certonly \
  --manual \
  --preferred-challenges=dns \
  --manual-auth-hook ./certbot-manual-freedns \
  --manual-cleanup-hook ./certbot-manual-freedns \
  -n \
  -d "$2"

new_cert=/etc/letsencrypt/live/$2/fullchain.pem
if [ -f "$new_cert" ]; then
  openssl x509 \
    -in "$new_cert" \
    -noout \
    -text
fi