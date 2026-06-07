namespace :ztlp do
  namespace :ns do
    desc "Reconcile ZtlpDevice rows against NS state"
    task sync: :environment do
      unless Ztlp::SyncState.due?
        next_at = Ztlp::SyncState.current[:next_retry_at]
        puts "[ztlp:ns:sync] skipped (next_retry_at=#{next_at&.iso8601 || 'unknown'})"
        next
      end

      result = Ztlp::SyncNsToBootstrap.call

      puts "[ztlp:ns:sync] status=#{result.status} " \
           "created=#{result.created} updated=#{result.updated} " \
           "orphaned=#{result.orphaned} skipped=#{result.skipped} " \
           "errors=#{result.errors.size}"

      result.errors.first(10).each do |e|
        puts "  skip: #{e[:name]} (#{e[:reason]})"
      end

      # AuditLog#status is validated against %w[success failure]; map our
      # Result#status (:ok / :error) into that vocabulary.
      audit_status = result.error? ? "failure" : "success"

      AuditLog.create!(
        action: "ztlp.ns.sync",
        status: audit_status,
        details: {
          created:  result.created,
          updated:  result.updated,
          orphaned: result.orphaned,
          skipped:  result.skipped,
          errors:   result.errors.first(20)
        }.to_json
      )

      # Persist sync health so the next cron tick can self-throttle during
      # NS outages (exp backoff 1m → 2m → 4m → 8m → 15m cap).
      if result.error?
        # result.message is shaped "ExceptionClass: message text" by the
        # service (see sync_ns_to_bootstrap.rb). We persist ONLY the class
        # name so /api/v1/sync_health and the dashboard banner don't leak
        # transport error details. Split on ": " (colon-SPACE) so namespaced
        # classes like "Ztlp::NsAdminClient::TransportError" survive intact.
        error_class = (result.message.to_s.split(": ", 2).first.presence) || "UnknownError"
        Ztlp::SyncState.record_failure!(error_class: error_class)
      else
        Ztlp::SyncState.record_success!
      end

      # Don't `exit` from inside the task — it disrupts tests and cron will
      # retry on its own schedule. Opt-in hard-fail via env var for ops who
      # want non-zero exits from a manual invocation.
      if result.error? && ENV["ZTLP_NS_SYNC_FAIL_HARD"] == "true"
        abort "[ztlp:ns:sync] sync errored; exiting non-zero per ZTLP_NS_SYNC_FAIL_HARD=true"
      end
    end
  end
end
