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
    def self.run(zone, admin: nil, publisher: nil, sleep: nil)
      publisher ||= NsClientPublisherProxy.new
      sleep ||= ->(secs) { Kernel.sleep(secs) }

      writes = [
        -> { publisher.authority!(zone, admin: admin) },
        -> { zone.users.where(status: "active").order(:username).each { |u| publisher.publish_user!(u, admin: admin) } },
        -> { zone.groups.order(:name).each { |g| publisher.publish_group!(g, admin: admin) } },
        -> { zone.devices.where(status: "enrolled").order(:name).each { |d| publisher.publish_device!(d, admin: admin) } }
      ]

      total = count_writes(zone)
      writes.each_with_index do |w, i|
        w.call
        # No trailing sleep after the last write.
        sleep.call(PUBLISH_INTERVAL) if i < total - 1
      end
      :ok
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
