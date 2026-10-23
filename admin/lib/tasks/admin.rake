# frozen_string_literal: true

# Administrator break-glass (spec §4.1 step 6). Run INSIDE the web container on the host,
# over SSH with certificate auth — never a web route:
#
#   docker exec ztlp-admin-web /rails/bin/docker-entrypoint ./bin/rails admin:reset_claim
#
# It reuses Claim.issue!(force: true), which bypasses the no-admins check and prints a fresh
# 24h claim code. Claiming with that code (POST /claim, signature optional — the code alone
# proves host access) creates an ADDITIONAL super_admin via Claim.perform!(force: true)
# without touching the existing administrators, and audits system.reset_claim.
namespace :admin do
  desc "Break-glass: issue a fresh 24h claim code even when administrators exist"
  task reset_claim: :environment do
    code = Claim.issue!(force: true)
    AuditLog.record!("system.reset_claim",
                                details: { via: "rake:admin:reset_claim" })
    puts <<~RUNBOOK
      ZTLP ADMIN break-glass: a fresh claim code was issued (valid 24h).

      #{code}

      Claim it through the tunnel exactly like the first run (POST /claim or the
      ztlp-admin-sign.py flow). It creates an ADDITIONAL super_admin; existing
      administrators are not touched.

      Host runbook line:
        docker exec ztlp-admin-web /rails/bin/docker-entrypoint ./bin/rails admin:reset_claim
    RUNBOOK
  end
end
