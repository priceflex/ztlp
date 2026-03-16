# frozen_string_literal: true

require "open3"

# Auto-enroll the Bootstrap server as a ZTLP device at boot.
#
# This generates a ZTLP identity (Ed25519 keypair + NodeID) so the
# Bootstrap app can use ZTLP tunnels for health checks and metrics
# collection. The identity is stored in ZTLP_IDENTITY_DIR (~/.ztlp/).
#
# If an identity already exists, this is a no-op.
# If no network exists yet, enrollment is skipped (will happen on first deploy).

Rails.application.config.after_initialize do
  next unless Rails.env.production? || ENV["ZTLP_AUTO_ENROLL"] == "true"

  identity_dir = ENV.fetch("ZTLP_IDENTITY_DIR", File.expand_path("~/.ztlp"))
  identity_file = File.join(identity_dir, "identity.json")
  ztlp_cli = ENV.fetch("ZTLP_CLI_PATH", "ztlp")

  # Skip if already enrolled
  next if File.exist?(identity_file)

  # Skip if CLI not available
  unless system("#{ztlp_cli} --version", out: File::NULL, err: File::NULL)
    Rails.logger.info("[ZTLP Enrollment] CLI not available at #{ztlp_cli} — skipping auto-enrollment")
    next
  end

  # Find the first network with an NS server
  network = Network.joins(:machines).where(machines: { roles: "ns" }).first
  unless network
    Rails.logger.info("[ZTLP Enrollment] No network with NS found — skipping auto-enrollment")
    next
  end

  ns_machine = network.ns_machines.first
  unless ns_machine
    Rails.logger.info("[ZTLP Enrollment] No NS machine found — skipping auto-enrollment")
    next
  end

  # Generate enrollment token for Bootstrap itself
  begin
    generator = TokenGenerator.new(network)
    token = generator.generate!(
      expires_in: 365.days,
      max_uses: 1,
      notes: "Auto-enrollment for Bootstrap server"
    )

    token_uri = token.token_uri
    Rails.logger.info("[ZTLP Enrollment] Enrolling Bootstrap with NS at #{ns_machine.ip_address}...")

    # Run enrollment — --token skips interactive menu, --name provides device name
    hostname = `hostname`.strip.gsub(/[^a-zA-Z0-9._-]/, "").downcase
    device_name = "bootstrap-#{hostname}"[0..62] # Max 63 chars

    output, status = Open3.capture2e(
      ztlp_cli, "setup", "--token", token_uri, "--name", device_name,
      chdir: identity_dir
    )

    if status.success?
      Rails.logger.info("[ZTLP Enrollment] ✅ Bootstrap enrolled successfully")
      token.use! # Mark token as used
    else
      Rails.logger.warn("[ZTLP Enrollment] ⚠ Enrollment failed: #{output.truncate(200)}")
    end
  rescue StandardError => e
    Rails.logger.warn("[ZTLP Enrollment] ⚠ Auto-enrollment error: #{e.message}")
  end
end
