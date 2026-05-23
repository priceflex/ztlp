# frozen_string_literal: true

# Operator rake tasks for the EnrollmentToken lifecycle.
#
# Run from a cron / scheduler (Solid Queue, sidekiq-cron, host crontab —
# whatever the bootstrap deployment uses). Idempotent so repeated runs
# are safe.
#
# Usage:
#   bundle exec rails ztlp:tokens:sweep_expired
#   bundle exec rails ztlp:tokens:stats
#
# Both tasks write to STDOUT in a one-line summary so cron output is
# greppable. `sweep_expired` also writes an AuditLog summary entry
# whenever any token is transitioned.
namespace :ztlp do
  namespace :tokens do
    desc "Mark all active-but-past-expiry enrollment tokens as expired (BS-PR-1)"
    task sweep_expired: :environment do
      pre = Time.current
      count = EnrollmentToken.sweep_expired!
      took_ms = ((Time.current - pre) * 1000).round
      puts "[ztlp:tokens:sweep_expired] transitioned=#{count} took=#{took_ms}ms at=#{pre.iso8601}"
    end

    desc "Print enrollment-token counts grouped by status"
    task stats: :environment do
      counts = EnrollmentToken.group(:status).count
      EnrollmentToken::VALID_STATUSES.each do |s|
        counts[s] ||= 0
      end

      puts "[ztlp:tokens:stats] " + counts.map { |k, v| "#{k}=#{v}" }.join(" ")
    end
  end
end
