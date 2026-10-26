# frozen_string_literal: true

module Ztlp
  # Is the gateway on the name server? (slice 5: "Check now" + GatewayStatusJob). A gateway
  # publishes its own SVC record; finding it means online. A gateway that was online/registered and
  # has disappeared goes stale; a planned one stays planned until its first SVC shows up.
  class GatewayStatus
    def self.check!(gateway, ns_client: NsClient)
      record = ServiceRegistrar.lookup(gateway.ns_name, gateway.zone, ns_client: ns_client)
      return :not_configured if record == :not_configured

      if record
        data = record[:data] || {}
        gateway.update!(status: "online", last_svc_seen_at: Time.current,
                        node_id_hex: data["node_id"].presence || gateway.node_id_hex,
                        addresses: ServiceRegistrar.addresses_of(data).presence || gateway.addresses)
        :online
      else
        gateway.update!(status: "stale") if %w[online registered].include?(gateway.status)
        :not_found
      end
    end
  end
end
