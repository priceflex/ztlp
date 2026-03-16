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

  # Record types
  SVC_RECORD = 0x02   # Service record (addr:port)
  KEY_RECORD = 0x01   # Key record (pubkey)

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

  # Send a SVC registration to the NS via UDP
  def register_svc(ns_host, ns_port, name, addr, ttl)
    name_bytes = name.encode("UTF-8")
    addr_bytes = addr.encode("UTF-8")

    # Wire format: 0x02 + name_len(2) + name + record_type(1) + TTL(4) + data_len(2) + data
    packet = [0x02].pack("C")
    packet << [name_bytes.bytesize].pack("n")
    packet << name_bytes
    packet << [SVC_RECORD].pack("C")
    packet << [ttl].pack("N")
    packet << [addr_bytes.bytesize].pack("n")
    packet << addr_bytes

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

    unless response && response.bytesize >= 2
      raise RegistrationError, "No response from NS at #{ns_host}:#{ns_port}"
    end

    # Response format: response_type(1) + status(1) + ...
    resp_type = response.getbyte(0)
    status = response.getbyte(1)

    # 0x02 response type 0x00 = success
    unless status == 0x00
      error_msg = case status
                  when 0x01 then "name already taken"
                  when 0x02 then "invalid name"
                  when 0x03 then "auth required"
                  when 0x04 then "rate limited"
                  else "unknown error (0x#{status.to_s(16)})"
                  end
      raise RegistrationError, "NS registration failed: #{error_msg}"
    end

    true
  end

  # Query a SVC record from the NS
  def query_svc(ns_host, ns_port, name)
    name_bytes = name.encode("UTF-8")

    # Wire format: 0x01 (QUERY) + name_len(2) + name + record_type(1)
    packet = [0x01].pack("C")
    packet << [name_bytes.bytesize].pack("n")
    packet << name_bytes
    packet << [SVC_RECORD].pack("C")

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

    resp_type = response.getbyte(0)
    status = response.getbyte(1)

    # 0x02 response with 0x00 status = found
    return nil unless status == 0x00

    # Parse the SVC record data from response
    # Response: type(1) + status(1) + data_len(2) + data
    return nil if response.bytesize < 4

    data_len = response[2..3].unpack1("n")
    return nil if response.bytesize < 4 + data_len

    response[4, data_len]
  end
end
