# frozen_string_literal: true

# Service layer for interacting with the ZTLP NS Certificate Authority.
#
# Communicates with the NS server's CertAuthority module to manage
# the internal CA, issue certificates, and handle revocations.
class CaService
  attr_reader :network

  def initialize(network)
    @network = network
    @ns_registrar = NsRegistrar.new(network)
  end

  # Check CA initialization status
  def status
    # Query the NS for CA status via API
    result = ns_request("ca/status")
    {
      initialized: result[:initialized] || false,
      zone: result[:zone] || network.zone,
      root_key: result[:root_key],
      intermediate_key: result[:intermediate_key],
      created_at: result[:created_at],
      cert_count: network.certificates.count,
      active_certs: network.certificates.active.count,
      expiring_soon: network.certificates.expiring_soon.count
    }
  rescue StandardError => e
    { initialized: false, error: e.message }
  end

  # Initialize the CA for this network's zone
  def init_ca
    result = ns_request("ca/init", method: :post, body: { zone: network.zone })
    { success: true, root_key: result[:root_key] }
  rescue StandardError => e
    { success: false, error: e.message }
  end

  # Export root CA certificate (PEM)
  def export_root_cert
    result = ns_request("ca/root.pem")
    result[:pem]
  rescue StandardError
    nil
  end

  # Issue a certificate for a hostname
  def issue_cert(hostname:, days: 90, assurance_level: "software")
    result = ns_request("ca/issue", method: :post, body: {
      hostname: hostname,
      days: days,
      assurance_level: assurance_level
    })

    if result[:serial]
      cert = network.certificates.create!(
        hostname: hostname,
        serial: result[:serial],
        subject: "CN=#{hostname}",
        issuer: "ZTLP Intermediate CA (#{network.zone})",
        status: "active",
        assurance_level: assurance_level,
        issued_at: Time.current,
        expires_at: days.days.from_now,
        pem_data: result[:pem]
      )
      { success: true, certificate: cert }
    else
      { success: false, error: result[:error] || "Failed to issue certificate" }
    end
  rescue StandardError => e
    { success: false, error: e.message }
  end

  # Revoke a certificate
  def revoke_cert(certificate, reason: "unspecified")
    ns_request("ca/revoke", method: :post, body: {
      serial: certificate.serial,
      reason: reason
    })
    certificate.revoke!(reason: reason)
    { success: true }
  rescue StandardError => e
    { success: false, error: e.message }
  end

  # Rotate intermediate CA
  def rotate_intermediate
    result = ns_request("ca/rotate-intermediate", method: :post)
    { success: true, new_key: result[:intermediate_key] }
  rescue StandardError => e
    { success: false, error: e.message }
  end

  private

  def ns_request(path, method: :get, body: nil)
    # Use the NS registrar's connection to reach the CA API
    # This follows the same pattern as NsRegistrar for NS communication
    ns_url = @ns_registrar.send(:ns_url)
    uri = URI.parse("#{ns_url}/api/v1/#{path}")

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"
    http.open_timeout = 5
    http.read_timeout = 10

    request = case method
              when :post
                req = Net::HTTP::Post.new(uri.path, "Content-Type" => "application/json")
                req.body = body.to_json if body
                req
              else
                Net::HTTP::Get.new(uri.path)
              end

    response = http.request(request)

    if response.code.to_i >= 200 && response.code.to_i < 300
      JSON.parse(response.body, symbolize_names: true)
    else
      raise "NS request failed (#{response.code}): #{response.body}"
    end
  rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, Net::OpenTimeout => e
    raise "Cannot reach NS server: #{e.message}"
  end
end
