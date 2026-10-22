# frozen_string_literal: true

# Zone rake tasks (Slice 5a).
#
# The zone authority seed and the three zone secrets are host-level
# operations: they never have a web route. `zone:import_authority` reads the
# operator's identity.json (placed on the host per decision 11) and stores its
# `signing_key_seed` (64-hex Ed25519 seed) as-is; `zone:set_secret` reads the
# secret from STDIN only — never argv, never a flag — and validates the 64-hex
# shape before storing. Both audit what was stored (pubkey for the seed; the
# secret's own hash-free fact of being set, never its value).
namespace :zone do
  desc "Import the zone authority seed from an identity.json file (path required; pubkey is printed, the seed is not)"
  task :import_authority, [ :path ] do |_t, args|
    require "json"
    # Rake loads task files before Rails initializers run, so the app may not
    # be fully initialized. Ensure it is (no-op if already initialized).
    Rails.application.initialize! unless Rails.application.initialized?

    path = args.fetch(:path) { raise StandardError, "zone:import_authority requires a path: rails zone:import_authority[/path/to/identity.json]" }
    doc = JSON.parse(File.read(path))
    seed = doc.is_a?(Hash) ? doc["signing_key_seed"] : nil
    raise StandardError, "identity.json has no signing_key_seed" unless seed.is_a?(String) && seed.match?(/\A\h{64}\z/)

    # Derive the Ed25519 pubkey from the seed (cross-checked in Slice 4: pure
    # Python / OpenSSL / Ruby all agree).
    key = OpenSSL::PKey.new_raw_private_key("ED25519", [ seed ].pack("H*"))
    pubkey = key.raw_public_key.unpack1("H*")

    zone = Zone.primary
    zone.authority_seed_ct = seed
    zone.authority_pubkey_hex = pubkey
    zone.save!
    AuditLog.record!("zone.authority_imported", target: zone, details: { pubkey_hex: pubkey })
    puts "zone #{zone.name}: authority imported, pubkey #{pubkey[0, 16]}..."
  end

  desc "Set a zone secret from STDIN: rails zone:set_secret[enrollment|relay|ns_admin_api]"
  task :set_secret, [ :which ] do |_t, args|
    require "json"
    # Rake loads task files before Rails initializers run — ensure the app is
    # initialized (no-op if already done).
    Rails.application.initialize! unless Rails.application.initialized?
    which = args.fetch(:which)
    raise StandardError, "unknown secret: #{which} (expected enrollment, relay or ns_admin_api)" unless %w[enrollment relay ns_admin_api].include?(which)

    value = $stdin.gets.to_s.strip
    raise StandardError, "empty value on stdin; nothing stored" if value.empty?
    raise StandardError, "secret must be 64 hex chars" unless value.match?(/\A\h{64}\z/)

    zone = Zone.primary
    zone.send("#{which}_secret_ct=", value)
    zone.save!
    AuditLog.record!("zone.#{which}_secret_set", target: zone, details: { length: value.length })
    puts "zone #{zone.name}: #{which} secret set"
  end
end
