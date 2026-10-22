# frozen_string_literal: true

module Ztlp
  # The 6-hourly re-publish (spec Slice 5). Re-writes every record the panel
  # owns so the NS copy never goes stale: the zone's authority KEY, every
  # ACTIVE user, every group, every ENROLLED device — in that order, spaced
  # ~1.1 s between writes (NS rate-limit headroom).
  #
  # Every write flows through Ztlp::Publisher (the injectable `publisher:`
  # seam; the real one audits `ns.publish` with {name, type, result} — never
  # the record data). The `sleep:` seam is a callable the test replaces with
  # a recorder so the suite never really sleeps 1.1 s per write.
  class Republisher
    PUBLISH_INTERVAL = 1.1

    # `publisher:` must respond to `publish_user!`, `publish_group!`,
    # `publish_device!`, and `authority!`, each taking the entity/zone first
    # and `ns_client:`/`admin:` keyword args (the Ztlp::Publisher contract).
    # `sleep:` is a callable taking the seconds to sleep (default: Kernel).
    # Returns :no_authority (nothing written) when the zone has no authority seed yet,
    # otherwise { ok: <count>, failed: [<ns names>] }. One rejected write (rate limit,
    # timeout) is audited by Publisher and does NOT stop the remaining writes.
    def self.run(zone, admin: nil, publisher: nil, sleep: nil)
      return :no_authority unless zone.authority_configured?

      publisher ||= NsClientPublisherProxy.new
      sleep ||= ->(secs) { Kernel.sleep(secs) }

      writes = [ [ zone.name, -> { publisher.authority!(zone, admin: admin) } ] ]
      zone.users.where(status: "active").order(:username).each do |u|
        writes << [ u.ns_name, -> { publisher.publish_user!(u, admin: admin) } ]
      end
      zone.groups.order(:name).each { |g| writes << [ g.ns_name, -> { publisher.publish_group!(g, admin: admin) } ] }
      zone.devices.where(status: "enrolled").order(:name).each do |d|
        writes << [ d.ns_name, -> { publisher.publish_device!(d, admin: admin) } ]
      end

      ok = 0
      failed = []
      writes.each_with_index do |(name, write), i|
        sleep.call(PUBLISH_INTERVAL) if i.positive? # one gap between EVERY pair of record writes
        begin
          write.call
          ok += 1
        rescue NsClient::NsError
          failed << name
        end
      end
      { ok: ok, failed: failed }
    end

    # Total NS writes the republisher will make for `zone`.
    def self.count_writes(zone)
      1 + # authority KEY
        zone.users.where(status: "active").count +
        zone.groups.count +
        zone.devices.where(status: "enrolled").count
    end

    # The default publisher: Ztlp::Publisher's own class methods, wrapped so
    # the seam contract (keyword `admin:`) matches. Kept as a small constant
    # class so the default is inspectable and the /zone "Publish now" button
    # works without an inject.
    class NsClientPublisherProxy
      def publish_user!(user, ns_client: NsClient, admin: nil, **kw)
        Publisher.publish_user!(user, ns_client: ns_client, admin: admin, **kw)
      end

      def publish_group!(group, ns_client: NsClient, admin: nil, **kw)
        Publisher.publish_group!(group, ns_client: ns_client, admin: admin, **kw)
      end

      def publish_device!(device, ns_client: NsClient, admin: nil, **kw)
        Publisher.publish_device!(device, ns_client: ns_client, admin: admin, **kw)
      end

      def authority!(zone, ns_client: NsClient, admin: nil, **kw)
        Publisher.publish_authority!(zone, ns_client: ns_client, admin: admin, **kw)
      end
    end
  end
end
