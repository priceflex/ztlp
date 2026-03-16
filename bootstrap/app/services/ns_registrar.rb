# frozen_string_literal: true

require "socket"

# Registers Bootstrap app as a service record in the ZTLP Namespace Server.
# This allows ZTLP nodes to discover the Bootstrap UI via NS lookup:
#   ztlp ns lookup bootstrap.<zone> --ns-server <ns_addr>
#
# Registration uses the NS wire protocol:
#   0x02 (REGISTER) + name_len(2) + name + record_type(1) + TTL(4) + data_len(2) + data
class NsRegistrar
  class RegistrationError < StandardError; end

  # NS wire protocol opcodes
  OPCODE_QUERY    = 0x01
  OPCODE_REGISTER = 0x09

  # Record types (byte values)
  TYPE_KEY   = 0x01
  TYPE_SVC   = 0x02
  TYPE_RELAY = 0x03

  # Default TTL: 5 minutes (re-register periodically)
  DEFAULT_TTL = 300

  def initialize(network)
    @network = network
  end

  # Register Bootstrap as a service in the NS
  # Returns true on success, raises RegistrationError on failure
  def register!(bootstrap_url: nil, ttl: DEFAULT_TTL)
    ns_machine = @network.ns_machines.first
    raise RegistrationError, "No NS machine configured for network #{@network.name}" unless ns_machine

    ns_port = SshProvisioner::ZTLP_PORTS["ns"][:udp]
    ns_addr = "#{ns_machine.ip_address}:#{ns_port}"

    # Determine Bootstrap address to register
    url = bootstrap_url || ENV.fetch("BOOTSTRAP_URL", nil)
    raise RegistrationError, "BOOTSTRAP_URL not configured" unless url

    # Extract host:port from URL
    uri = URI.parse(url)
    bootstrap_addr = "#{uri.host}:#{uri.port}"

    # Service name: bootstrap.<zone>
    service_name = "bootstrap.#{@network.zone}"

    # Build and send registration packet
    register_svc(ns_machine.ip_address, ns_port, service_name, bootstrap_addr, ttl)

    { name: service_name, addr: bootstrap_addr, ns: ns_addr, ttl: ttl }
  end

  # Query the NS for Bootstrap's registration
  def lookup
    ns_machine = @network.ns_machines.first
    return nil unless ns_machine

    ns_port = SshProvisioner::ZTLP_PORTS["ns"][:udp]
    service_name = "bootstrap.#{@network.zone}"

    query_svc(ns_machine.ip_address, ns_port, service_name)
  end

  # Check if Bootstrap is registered
  def registered?
    lookup.present?
  end

  private

  # Minimal CBOR encoder for NS record data.
  # Only supports strings, integers, and maps — sufficient for SVC records.
  module MiniCbor
    module_function

    def encode(term)
      case term
      when String
        encode_head(3, term.bytesize) + term.b
      when Integer
        if term >= 0
          encode_head(0, term)
        else
          encode_head(1, -1 - term)
        end
      when Hash
        # Sort keys by encoded length then bytes (RFC 8949 §4.2.1)
        pairs = term.map { |k, v| [encode(k.to_s), encode(v)] }
                     .sort_by { |ek, _| [ek.bytesize, ek] }
        encode_head(5, term.size) + pairs.map { |ek, ev| ek + ev }.join
      when TrueClass then "\xf5".b
      when FalseClass then "\xf4".b
      when NilClass then "\xf6".b
      else
        raise ArgumentError, "MiniCbor: unsupported type #{term.class}"
      end
    end

    def encode_head(major, n)
      mt = major << 5
      if n < 24
        [(mt | n)].pack("C")
      elsif n < 0x100
        [(mt | 24), n].pack("CC")
      elsif n < 0x10000
        [(mt | 25)].pack("C") + [n].pack("n")
      elsif n < 0x100000000
        [(mt | 26)].pack("C") + [n].pack("N")
      else
        [(mt | 27)].pack("C") + [n].pack("Q>")
      end
    end
  end

  # Send a SVC registration to the NS via UDP.
  #
  # NS wire format for unsigned registration (v1 without pubkey):
  #   0x09 + name_len(2) + name + type_byte(1) + data_len(2) + data + sig_len(2) + sig_placeholder
  #
  # Note: NS must have ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false to accept
  # unsigned registrations. The sig is a zeroed placeholder.
  def register_svc(ns_host, ns_port, name, addr, _ttl)
    name_bytes = name.encode("UTF-8")

    # CBOR-encode the service record data as a map
    svc_data = {
      "addr" => addr,
      "type" => "bootstrap",
      "protocol" => "http"
    }
    data_bytes = MiniCbor.encode(svc_data)

    sig_placeholder = "\x00".b * 64  # Ed25519 signature placeholder

    packet = [OPCODE_REGISTER].pack("C")                    # 0x09
    packet << [name_bytes.bytesize].pack("n")                # name_len (2 bytes, big-endian)
    packet << name_bytes                                     # name
    packet << [TYPE_SVC].pack("C")                           # record type (SVC = 0x02)
    packet << [data_bytes.bytesize].pack("n")                # data_len (2 bytes)
    packet << data_bytes                                     # data (CBOR-encoded map)
    packet << [sig_placeholder.bytesize].pack("n")           # sig_len (2 bytes)
    packet << sig_placeholder                                # sig placeholder

    sock = UDPSocket.new
    sock.send(packet, 0, ns_host, ns_port)

    # Wait for response
    response = nil
    begin
      ready = IO.select([sock], nil, nil, 5)
      if ready
        data, = sock.recvfrom(1024)
        response = data
      end
    ensure
      sock.close
    end

    unless response && response.bytesize >= 1
      raise RegistrationError, "No response from NS at #{ns_host}:#{ns_port}"
    end

    # Check response: 0xFF = error/unknown, anything else we check for success
    first_byte = response.getbyte(0)

    if first_byte == 0xFF
      raise RegistrationError, "NS rejected registration (0xFF — auth may be required)"
    end

    # Success responses vary by NS version; non-0xFF means accepted
    true
  end

  # Query a SVC record from the NS
  #
  # NS query wire format:
  #   0x01 + name_len(2) + name + type_byte(1)
  #
  # Response format:
  #   0x02 + record_data (on success)
  #   0xFF (not found / error)
  def query_svc(ns_host, ns_port, name)
    name_bytes = name.encode("UTF-8")

    packet = [OPCODE_QUERY].pack("C")
    packet << [name_bytes.bytesize].pack("n")
    packet << name_bytes
    packet << [TYPE_SVC].pack("C")

    sock = UDPSocket.new
    sock.send(packet, 0, ns_host, ns_port)

    response = nil
    begin
      ready = IO.select([sock], nil, nil, 5)
      if ready
        data, = sock.recvfrom(4096)
        response = data
      end
    ensure
      sock.close
    end

    return nil unless response && response.bytesize >= 2

    first_byte = response.getbyte(0)
    return nil if first_byte == 0xFF  # Not found

    # Response byte 0 is 0x02 (response type), byte 1+ is record data
    # Try to extract the address string from the response
    if response.bytesize > 2
      # Skip response header bytes and try to extract the data
      # The exact format depends on the NS response encoding
      response[1..]&.force_encoding("UTF-8")
    end
  end
end
