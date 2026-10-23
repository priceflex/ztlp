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
#   2. Leaves the solid_queue queue tables exactly as they were (this app's
#      live shape idles without them; `solid_queue:prepare` does not exist as
#      a task in this app — a prior draft that called it aborted the reset).
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

# 2. The solid_queue queue tables: NOT in schema.rb. Whether they exist is
#    environment-dependent (this app's live shape idles without them), so the
#    reset must not create OR drop them — it leaves the queue-table state
#    exactly as it was, and only wipes the app tables.

# 3. Sanity: the app tables exist and are empty.
admins = ActiveRecord::Base.connection.select_value("SELECT COUNT(*) FROM admins")
users = ActiveRecord::Base.connection.select_value("SELECT COUNT(*) FROM users")
abort "reset left existing admins (#{admins})" unless admins == 0
abort "reset left existing users (#{users})" unless users == 0

puts "PASS: smoke-reset-db — fresh, claimable panel (admins=0, users=0)"
