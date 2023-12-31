# certbot-manual-freedns

Renews certificates using DNS challenge against FreeDNS

## Usage
1. Install `certbot` following the official docs
2. Create `config.yaml` with FreeDNS credentials in the same directory as `certbot-manual-freedns`
3. Use `certbot-manual-freedns` as a manual hook.
    ```bash
    certbot \
      --agree-tos \
      --email me@example.com \
      --work-dir "$(pwd)" \
      certonly \
      --manual \
      --preferred-challenges=dns \
      --manual-auth-hook ./certbot-manual-freedns \
      --manual-cleanup-hook ./certbot-manual-freedns \
      -n \
      -d example.com
    ```
4. Enable auto renewal `systemctl enable --now snap.certbot.renew.timer`

## Testing
A manual shell script test is provided that hits certbot staging API to issue test certificates.
```bash
go build .
./certbot-test.sh me@example.com example.com
```

## Development
### Update mocks
```bash
go install github.com/vektra/mockery/v2@v2.35.3
mockery
```