# ZTLP Admin

Management panel for a ZTLP fleet. Specification: `../docs/ADMIN-PANEL-SPEC.md`.

Slice 1 (this build): first-administrator claim, passwordless Ed25519 login, administrator roles, audit log.

## Run

    cp .env.example .env   # edit
    docker compose up -d
    docker compose logs web | grep "Claim code"

Open the panel, paste the claim code and your `ed25519_public_key` from `ztlp keygen`.
To sign the claim or a login challenge without the CLI commands (slice 4), use the helper served at
`/ztlp-admin-sign.py` (reads `~/.ztlp/identity.json`, nothing leaves your machine).

## Develop

    docker run -d --name ztlp-admin-dev-db -e MARIADB_ROOT_PASSWORD=devroot -p 127.0.0.1:33061:3306 mariadb:11.4 \
      --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci
    bundle install && bin/rails db:prepare && RAILS_ENV=test bin/rails db:prepare
    bin/rails test
    bin/dev
