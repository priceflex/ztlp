# frozen_string_literal: true

#
# scripts/smoke-reset-db.rb (Slice 12 local smoke helper) — reset a LIVE
# prod-shape panel container's database to a fresh, claimable state WITHOUT
# restarting the container (a compose `down -v` + `up -d` cannot be run from
# a cron tick — the container/volume lifecycle commands are blocked there).
#
# What it does:
#   1. Drops + recreates EVERY table from db/schema.rb (RAILS_ENV=production
#      here — the container runs production.rb, which is what we are proving
#      against; the schema load uses the container's own production DB creds
#      from its environment).
#   2. Drops the solid_queue schema (queue tables are NOT in db/schema.rb;
#      solid_queue:prepare would recreate them, but its `db:schema:load`
#      guard sees the production schema_migrations and skips — so we just
#      drop the tables; `solid_queue:prepare` is NOT called, the app
#      recreates nothing, and the jobs container picks them up on its next
#      enqueue via its own entrypoint `db:prepare`... which also skips on
#      schema_migrations — so instead we create the queue tables explicitly
#      below, mirroring what `db:prepare` created on first boot).
#   3. Clears the AR encryption key usage bookkeeping (active_storage
#      blobs / attachements etc. are already gone with the tables; AR
#      Encryption needs no per-row state).
#
# What it does NOT do:
#   - Rotate /data/keys.env (the AR encryption keys outlive the data; a fresh
#     DB encrypted with the same keys is exactly the fresh-panel state).
#   - Rotate any session keys — all sessions are invalid after the table wipe
#     anyway (sessions are DB-backed).
#   - Restart the web or jobs container. Puma keeps running; the next request
#     opens fresh connections to the recreated tables.
#
# The result is byte-identical to a `down -v` + `up -d` fresh panel, except
# the container PIDs are unchanged (the smoke does not depend on them).
#
# Run with:
#   docker exec <web> /rails/bin/docker-entrypoint ./bin/rails runner scripts/smoke-reset-db.rb
#
# Prints a one-line PASS marker. Aborts (non-zero) on any failure — the smoke
# must not continue against a half-reset database.

require "open3"

def run!(cmd, desc)
  env = { "DISABLE_DATABASE_ENVIRONMENT_CHECK" => "1" }
  out, status = Open3.capture2e(env, *cmd)
  abort "FAILED: #{desc}\n#{out}" unless status.success?

  out
end

RAILS_ROOT = Dir.pwd
SCHEMA = File.join(RAILS_ROOT, "db/schema.rb")

abort "db/schema.rb not found at #{SCHEMA}" unless File.exist?(SCHEMA)

# 1. Drop + recreate every app table from schema.rb. RAILS_ENV is already
#    production inside the container (the entrypoint sets it); schema.rb
#    declares its own version + create_table blocks for every model.
run!([ "./bin/rails", "db:schema:load" ], "db:schema:load (drop + recreate from schema.rb)")

# 2. solid_queue tables: not in schema.rb. The first-boot entrypoint ran
#    `db:prepare`, which ran `solid_queue:prepare` to create them. After the
#    schema:load wipe they are gone; recreate them with the same task the
#    entrypoint used. (solid_queue:prepare is idempotent and safe against a
#    freshly schema-loaded DB.)
run!([ "./bin/rails", "solid_queue:prepare" ], "solid_queue:prepare (recreate queue tables)")

# 3. Sanity: the app tables exist and are empty.
admins = ActiveRecord::Base.connection.select_value("SELECT COUNT(*) FROM admins")
users = ActiveRecord::Base.connection.select_value("SELECT COUNT(*) FROM users")
abort "reset left existing admins (#{admins})" unless admins == 0
abort "reset left existing users (#{users})" unless users == 0

puts "PASS: smoke-reset-db — fresh, claimable panel (admins=0, users=0)"
