# frozen_string_literal: true

# Slice 5 of PLAN-services-wizard-and-helpdesk.md: the gateway install script.
#
# One copy-paste block a person runs (as root) on the gateway's box. It writes the same shape every
# production gateway runs today (compose, host networking, uid 1000, /data with a persistent QUIC
# cert, ZTLP_HMAC_SECRET_<ZONE> from .env), creates the identity inside the image only if there is
# none, and starts it. Secrets live ONLY in the .env block (mode 600), never in the compose file.
require "test_helper"
require "open3"

class GatewayInstallTest < ActiveSupport::TestCase
  RELAY = "relay-secret-NOT-hex_value"
  HEADER = "ab" * 32

  setup do
    @zone = Zone.primary
    @zone.update!(ns_addr: "203.0.113.10:23096", relay_addrs: [ "203.0.113.10:23095" ])
    @gw = @zone.gateways.create!(name: "www", kind: "rust_listen", status: "planned", host_note: "box",
                                 bind_port: 23_098, max_sessions: 50, punch: false, inject_headers: true,
                                 header_secret_ct: HEADER, policy_file: true,
                                 subject_map: [ "#{'cd' * 32}=steve" ])
    @svc = @gw.services.create!(name: "www", backend: "http://172.20.0.2:80", protocol: "http")
    @svc.policy_rules.create!(subject_type: "role", subject_value: "tech", position: 0)
  end

  def script(**kw) = Ztlp::GatewayInstall.script(@gw, relay_secret: RELAY, header_secret: HEADER, **kw)

  test "the script is valid bash and stops on the first error" do
    out, status = Open3.capture2e("bash", "-n", stdin_data: script)
    assert status.success?, "bash -n: #{out}"
    assert_match(/\Aset -euo pipefail$/, script.lines.grep(/\Aset /).first.to_s)
  end

  test "it installs into one directory per service name" do
    assert_includes script, "DIR=/opt/ztlp-gateway-www-#{@zone.name.tr('.', '-')}"
  end

  test "secrets appear only in the .env block, never in the compose file" do
    compose = Ztlp::GatewayInstall.compose(@gw)
    assert_not_includes compose, RELAY
    assert_not_includes compose, HEADER
    env_block = script[/cat > \.env <<'ZTLP_ENV'\n(.*?)\nZTLP_ENV/m, 1]
    assert_includes env_block, "#{Ztlp::ServiceRegistrar.relay_env_var(@zone)}=#{RELAY}"
    assert_includes env_block, "GATEWAY_HEADER_SECRET=#{HEADER}"
    assert_equal 1, script.scan(RELAY).size
    assert_equal 1, script.scan(HEADER).size
    assert_includes script, "chmod 600 .env"
  end

  test "the compose file carries every parameter, production shape" do
    c = Ztlp::GatewayInstall.compose(@gw)
    [ "image: ztlp-gateway-rust:v0.36.0", "network_mode: host", 'user: "1000:1000"', "ZTLP_QUIC_CERT_DIR: /data/quic-cert",
      "#{Ztlp::ServiceRegistrar.relay_env_var(@zone)}: \"${#{Ztlp::ServiceRegistrar.relay_env_var(@zone)}}\"",
      "- ./data:/data", 'entrypoint: ["ztlp"]', "- listen", "- --gateway", "- 0.0.0.0:23098", "- /data/identity.json",
      "- www:172.20.0.2:80", "- 203.0.113.10:23096", "- 203.0.113.10:23095", "- --service-name", "- --zone",
      "- #{@zone.name}", "- --ns-register-name", "- www.#{@zone.name}", "- --max-sessions", "- \"50\"",
      "- --policy", "- /data/policy.toml", "- --no-punch", "- --http-inject-headers", "- --header-hmac-secret",
      '- "${GATEWAY_HEADER_SECRET}"', "- --admin-pubkey-email", "- \"#{'cd' * 32}=steve\"" ].each do |line|
      assert_includes c, line, "compose is missing #{line}"
    end
  end

  test "optional flags follow the settings" do
    @gw.update!(punch: true, inject_headers: false, header_secret_ct: nil, subject_map: nil, relay_addr: nil, policy_file: true)
    @zone.update!(relay_addrs: nil)
    c = Ztlp::GatewayInstall.compose(@gw)
    %w[--no-punch --http-inject-headers --header-hmac-secret --admin-pubkey-email --relay].each do |flag|
      assert_not_includes c, "- #{flag}\n", "#{flag} must be absent"
    end
    assert_not_includes Ztlp::GatewayInstall.script(@gw, relay_secret: RELAY, header_secret: nil), "GATEWAY_HEADER_SECRET"
  end

  test "the rendered policy goes to data/policy.toml" do
    assert_includes script, "cat > data/policy.toml <<'ZTLP_POLICY'"
    assert_includes script, 'allow = ["role:tech"]'
  end

  test "identity is created inside the image only when missing, then ownership and start" do
    s = script
    assert_match(%r{\[ -s data/identity\.json \] \|\| docker run --rm --user 0:0 -v "\$DIR/data:/data" --entrypoint ztlp "\$IMAGE" keygen --output /data/identity\.json}, s)
    assert s.index("keygen") < s.index("chown -R 1000:1000 data")
    assert s.index("chown -R 1000:1000 data") < s.index("docker compose up -d")
  end

  test "a missing image is explained instead of a docker error" do
    @gw.update!(image_tag: "registry.example.com/ztlp-gateway:1.2")
    assert_match(/docker image inspect "\$IMAGE" .*\|\| docker pull "\$IMAGE" \|\| \{/, script)
    assert_includes script, "load it on this box first"
  end

  # Gap 2 of the whoami UI walkthrough: ztlp-gateway-rust:<tag> is not on any registry, so a fresh box
  # could not get the default image. The script now builds it from the public GitHub release.
  test "the default image is built from the GitHub release when the box does not have it" do
    @gw.update!(image_tag: nil)
    s = script
    v = Gateway.default_image[/:(v[\d.]+)\z/, 1]
    assert_includes s, "https://github.com/priceflex/ztlp/releases/download/#{v}"
    assert_includes s, %(PKG="ztlp-#{v}-$ARCH-unknown-linux-gnu")
    assert_includes s, %("#{"https://github.com/priceflex/ztlp/releases/download/#{v}"}/$PKG.tar.gz")
    assert_includes s, "SHA256SUMS.txt"
    assert_match(/sha256sum -c/, s)
    assert_match(/x86_64\|amd64\) ARCH=x86_64/, s)
    assert_match(/aarch64\|arm64\) ARCH=aarch64/, s)
    assert_includes s, "FROM ubuntu:24.04"
    assert_match(/docker build .*"\$IMAGE"/, s)
    refute_match(/docker pull/, s, "there is nothing to pull for the panel's own image")
  end

  test "the release build only runs when the image is missing" do
    @gw.update!(image_tag: nil)
    s = script
    assert_match(/if ! docker image inspect "\$IMAGE" >\/dev\/null 2>&1; then\n.*Building/m, s)
  end

  test "a custom image is still pulled, never built from GitHub" do
    @gw.update!(image_tag: "registry.example.com/ztlp-gateway:1.2")
    s = script
    assert_match(/docker pull "\$IMAGE"/, s)
    refute_includes s, "github.com/priceflex/ztlp/releases"
  end

  test "the script with the release build is valid bash" do
    @gw.update!(image_tag: nil)
    out, status = Open3.capture2e("bash", "-n", stdin_data: script)
    assert status.success?, out
  end

  test "the policy update block has no secrets and restarts only the gateway" do
    u = Ztlp::GatewayInstall.policy_update_script(@gw)
    assert_not_includes u, RELAY
    assert_not_includes u, HEADER
    assert_includes u, "cat > data/policy.toml <<'ZTLP_POLICY'"
    assert_includes u, "docker compose restart"
    out, status = Open3.capture2e("bash", "-n", stdin_data: u)
    assert status.success?, out
  end

  test "the app side gets the same header secret and the audience" do
    assert_equal "ZTLP_GATEWAY_HEADER_SECRET=#{HEADER}\nZTLP_GATEWAY_AUDIENCE=www\n",
                 Ztlp::GatewayInstall.app_env(@gw, header_secret: HEADER)
  end

  test "prerequisites: the zone relay secret and a backend on every service" do
    assert_includes Ztlp::GatewayInstall.missing(@gw), "the #{@zone.name} relay secret is not set in the panel"
    @zone.update!(relay_secret_ct: RELAY)
    assert_empty Ztlp::GatewayInstall.missing(@gw.reload)
    @svc.update!(backend: nil)
    assert_includes Ztlp::GatewayInstall.missing(@gw.reload), "service www has no backend"
  end

  test "values that could break out of the heredoc are refused" do
    assert_raises(Ztlp::GatewayInstall::Unsafe) do
      Ztlp::GatewayInstall.script(@gw, relay_secret: "x\nZTLP_ENV\nrm -rf /", header_secret: HEADER)
    end
  end
end
