#!/usr/bin/env bash

#set -x

VIRTUAL_ENV="$VIRTUAL_ENV"

set -euo pipefail

if [ ! -d "venv" ]; then
  echo "Creating virtualenv"
  python3 -m virtualenv venv
fi

if [ -z "$VIRTUAL_ENV" ]; then
  echo "Activating virtualenv"
  . venv/bin/activate
fi

if ! pip freeze | grep -q ^certbot; then
  echo "Setting up virtualenv"
  pip install -U pip setuptools wheel
  pip install -U certbot
fi

go build main.go
rm -rf venv/etc/*

conf_dir=$(pwd)/venv/etc
mkdir -p "$conf_dir"
log_dir=$(pwd)/venv/logs
mkdir -p "$log_dir"

certbot \
  --agree-tos \
  --email "$1" \
  --config-dir "$conf_dir" \
  --logs-dir "$log_dir" \
  --work-dir "$(pwd)" \
  certonly \
  --test-cert \
  --manual \
  --preferred-challenges=dns \
  --manual-auth-hook ./main \
  --manual-cleanup-hook ./main \
  -n \
  -d "$2"

new_cert=$conf_dir/live/$2/fullchain.pem
if [ -f "$new_cert" ]; then
  openssl x509 \
    -in "$new_cert" \
    -noout \
    -text
fi