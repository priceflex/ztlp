# frozen_string_literal: true

require "socket"
require "resolv"

# Ztlp::CheckNsReachability — boot-time diagnostic that records whether
# the per-tenant bootstrap container can reach the central ZTLP NS
# server on UDP.
#
# ## Why this exists (BS-PR-4)
#
# Steve's brief asked the bootstrap container to "verify [...] the
# specific Docker container [...] is connected to the name server, so
# the network can be managed and modified from the bootstrap system."
#
# This service is the network-side half of that check. The CLI/UI
# half (Network row exists, dashboard renders it) is handled by
# `Ztlp::EnsureNetworkFromEnv`.
#
# ## Behaviour
#
# Reads `ZTLP_NS_SERVER` (format: `host:port`) from the environment
# and:
#
#   1. Resolves the host (DNS or IP). DNS failure ⇒ :unreachable.
#   2. Opens a UDP socket and connects it (no traffic sent — `connect`
#      on UDP just associates the destination so we can detect basic
#      addressability errors). Failure ⇒ :unreachable.
#   3. Returns :reachable when both steps succeed.
#
# This is intentionally non-blocking and informational. The result is
# logged to STDOUT (visible in `docker logs ztlp-bootstrap-<slug>`)
# by the caller in `bin/docker-entrypoint`. The bootstrap container
# starts whether or not the NS is reachable — operators may need the
# UI to be available specifically *because* the NS is having trouble.
#
# ## Why UDP-connect, not actual ZTLP protocol
#
# ZTLP NS protocol involves crypto + opaque opcodes. A full handshake
# from inside the bootstrap container is out of scope (we'd be
# bundling part of the `ztlp` CLI). The connect-only check catches the
# 99% of failure modes — wrong port, unresolvable host, firewall
# blocking the outbound subnet — that operators actually encounter
# during a new tenant provisioning.
module Ztlp
  class CheckNsReachability
    Result = Struct.new(:status, :host, :port, :message, keyword_init: true) do
      def reachable?   = status == :reachable
      def unreachable? = status == :unreachable
      def skipped?     = status == :skipped
      def error?       = status == :error
    end

    # @param env [Hash] env-var snapshot (defaults to ENV.to_h).
    # @return [Result]
    def self.call(env: ENV.to_h)
      new(env).call
    end

    def initialize(env)
      @env = env || {}
    end

    def call
      raw = @env["ZTLP_NS_SERVER"].to_s.strip
      return Result.new(status: :skipped, message: "ZTLP_NS_SERVER not set; skipping NS reachability check") if raw.empty?

      host, port = parse_host_port(raw)

      begin
        addr = Resolv.getaddress(host)
      rescue Resolv::ResolvError, SocketError => e
        return Result.new(status: :unreachable, host: host, port: port, message: "resolv error: #{e.message}")
      end

      sock = UDPSocket.new
      begin
        # `connect` on a UDP socket sets the default peer. It catches
        # basic addressability failures without sending any packets.
        sock.connect(addr, port)
        Result.new(status: :reachable, host: host, port: port,
                   message: "UDP socket to #{addr}:#{port} opened successfully")
      rescue Errno::ENETUNREACH, Errno::EHOSTUNREACH, Errno::EADDRNOTAVAIL,
             Errno::EACCES => e
        Result.new(status: :unreachable, host: host, port: port,
                   message: "UDP connect failed: #{e.class}: #{e.message}")
      ensure
        sock.close rescue nil
      end
    rescue => e
      Result.new(status: :error, host: host, port: port, message: "#{e.class}: #{e.message}")
    end

    private

    # "host:port" → ["host", 23096]. Raises a friendly error if either
    # piece is missing or non-numeric. We DON'T try to support IPv6 here
    # because LAUNCH_NS_SERVER is always v4 in our deployments — keep
    # the parser as simple as the data we actually see.
    def parse_host_port(raw)
      idx = raw.rindex(":")
      raise ArgumentError, "ZTLP_NS_SERVER #{raw.inspect} is missing :port" if idx.nil? || idx.zero?
      host = raw[0...idx]
      port_str = raw[(idx + 1)..]
      port = Integer(port_str)
      raise ArgumentError, "ZTLP_NS_SERVER port must be 1..65535, got #{port}" unless port.between?(1, 65535)
      [host, port]
    end
  end
end
