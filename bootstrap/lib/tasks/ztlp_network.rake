# frozen_string_literal: true

# BS-PR-4: boot-time provisioning tasks.
#
# These tasks are called from `bin/docker-entrypoint` after `db:prepare`
# and `db:seed`, so the schema is guaranteed to exist when they run.
#
# Both tasks are idempotent and log a one-line summary on STDOUT so
# `docker logs ztlp-bootstrap-<slug>` is greppable.
#
# Manual usage:
#   bundle exec rails ztlp:network:ensure_from_env
#   bundle exec rails ztlp:network:check_ns_reachability
namespace :ztlp do
  namespace :network do
    desc "Auto-create the per-tenant Network row from ZONE / ORG_NAME env vars (BS-PR-4, idempotent)"
    task ensure_from_env: :environment do
      result = Ztlp::EnsureNetworkFromEnv.call_safely
      net = result.network
      net_id = net&.id
      net_zone = net&.zone
      net_name = net&.name
      puts "[ztlp:network:ensure_from_env] status=#{result.status} id=#{net_id.inspect} " \
           "zone=#{net_zone.inspect} name=#{net_name.inspect} message=#{result.message.inspect}"
    end

    desc "Log whether ZTLP_NS_SERVER is reachable from this container on UDP (BS-PR-4, non-blocking)"
    task check_ns_reachability: :environment do
      result = Ztlp::CheckNsReachability.call
      puts "[ztlp:network:check_ns_reachability] status=#{result.status} " \
           "host=#{result.host.inspect} port=#{result.port.inspect} " \
           "message=#{result.message.inspect}"
    end

    desc "Auto-seed the per-tenant Network with shared production NS+Relay Machine rows so token-mint works on first boot (idempotent)"
    task ensure_shared_machines: :environment do
      result = Ztlp::EnsureSharedMachines.call_safely
      machine_summary = Array(result.machines).map { |m| "#{m.hostname}@#{m.ip_address}/#{m.roles}" }.join(",")
      puts "[ztlp:network:ensure_shared_machines] status=#{result.status} " \
           "machines=[#{machine_summary}] message=#{result.message.inspect}"
    end
  end
end
