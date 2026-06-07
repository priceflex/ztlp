namespace :ztlp do
  namespace :ns do
    desc "Reconcile ZtlpDevice rows against NS state"
    task sync: :environment do
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

      # Don't `exit` from inside the task — it disrupts tests and cron will
      # retry on its own schedule. Opt-in hard-fail via env var for ops who
      # want non-zero exits from a manual invocation.
      if result.error? && ENV["ZTLP_NS_SYNC_FAIL_HARD"] == "true"
        abort "[ztlp:ns:sync] sync errored; exiting non-zero per ZTLP_NS_SYNC_FAIL_HARD=true"
      end
    end
  end
end
