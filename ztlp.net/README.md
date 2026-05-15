# ztlp.net

Domain/deployment workspace for the public ZTLP product control plane.

This folder is intentionally separate from `bootstrap/` so domain hosting, ngrok, DNS, TLS, and later production deployment assets live under the product domain boundary instead of inside the Rails app.

## Local test tunnel

For local product testing, `www.ztlp.net` can point at the local Rails bootstrap app through the ngrok Docker image.

Do not commit the ngrok token. Put it in `ztlp.net/.env.local` or export it in the shell:

```bash
cd /home/trs/projects/ztlp/ztlp.net
cp .env.local.example .env.local
# edit .env.local and set NGROK_AUTHTOKEN
bin/run-local-ngrok
```

Defaults:

```text
NGROK_DOMAIN=www.ztlp.net
BOOTSTRAP_URL=https://www.ztlp.net
ZTLP_BOOTSTRAP_UPSTREAM=3000
```

The wrapper runs this folder's `docker-compose.yml`, builds the Rails app from `../bootstrap`, starts it on host networking, and exposes `http://127.0.0.1:3000` publicly through `https://www.ztlp.net` via ngrok.

Steven's raw ngrok equivalent for quick testing is:

```bash
docker run -it -e NGROK_AUTHTOKEN=<token> ngrok/ngrok http 80 --url=www.ztlp.net
```

Use the wrapper for repo work because it keeps secrets out of Git and pins the local bootstrap service wiring.

## Files

- `docker-compose.yml` — local test composition for Rails bootstrap + ngrok.
- `bin/run-local-ngrok` — loads `.env.local` and starts the local test tunnel.
- `.env.local.example` — safe template. Copy to `.env.local`; never commit real secrets.

## Not for secrets

Never commit:

- `.env.local`
- ngrok authtokens
- Rails master keys
- Rails production encryption keys
- TLS private keys
