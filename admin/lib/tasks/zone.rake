# frozen_string_literal: true

# Zone rake tasks (Slice 5a). Host-level operations only: no web route ever
# reads or writes the zone authority seed or the zone secrets.
#
#   zone:import_authority[path]  identity.json signing_key_seed (64 hex) -> zones.authority_seed_ct
#                                Refuses to replace a DIFFERENT seed unless FORCE=1 (every record
#                                already signed by the old key would be orphaned).
#   zone:set_secret[which]       value from STDIN only (never argv).
#                                enrollment / ns_admin_api: 64 hex.
#                                relay: 48 alphanumerics, NOT hex (spec F20: the relay hex-decodes a
#                                hex secret, the Rust gateway uses ASCII bytes; a hex secret never verifies).
#   zone:export_authority        prints the seed for the backup runbook (spec section 452). Requires
#                                CONFIRM=1; audited with the pubkey, never the seed.
namespace :zone do
  secret_rules = {
    "enrollment" => [ /\A\h{64}\z/, "64 hex characters" ],
    "ns_admin_api" => [ /\A\h{64}\z/, "64 hex characters" ],
    "relay" => [ /\A(?!\h+\z)[A-Za-z0-9]{48}\z/, "48 alphanumeric characters, not hex (spec F20)" ]
  }.freeze

  desc "Import the zone authority seed from identity.json (FORCE=1 to replace a different seed)"
  task :import_authority, [ :path ] => :environment do |_t, args|
    path = args[:path].presence || abort("usage: rails zone:import_authority[/path/to/identity.json]")
    doc = JSON.parse(File.read(path))
    seed = doc.is_a?(Hash) ? doc["signing_key_seed"] : nil
    abort "identity.json has no 64-hex signing_key_seed" unless seed.is_a?(String) && seed.match?(/\A\h{64}\z/)

    pubkey = OpenSSL::PKey.new_raw_private_key("ED25519", [ seed ].pack("H*")).raw_public_key.unpack1("H*")
    zone = Zone.primary
    different = zone.authority_seed_ct.present? && zone.authority_seed_ct != seed
    if different && ENV["FORCE"] != "1"
      abort "zone #{zone.name} already has authority #{zone.authority_pubkey_hex.to_s[0, 16]}...; " \
            "importing a different key orphans every record it signed. Re-run with FORCE=1 to replace it."
    end

    replaced = different ? zone.authority_pubkey_hex : nil
    zone.update!(authority_seed_ct: seed, authority_pubkey_hex: pubkey)
    AuditLog.record!("zone.authority_imported", target: zone,
                                                details: { pubkey_hex: pubkey, replaced_pubkey_hex: replaced }.compact)
    puts "zone #{zone.name}: authority imported, pubkey #{pubkey[0, 16]}..."
  end

  desc "Set a zone secret from STDIN: rails zone:set_secret[enrollment|relay|ns_admin_api]"
  task :set_secret, [ :which ] => :environment do |_t, args|
    which = args[:which].to_s
    rule, rule_text = secret_rules[which]
    abort "unknown secret '#{which}' (expected #{secret_rules.keys.join(", ")})" unless rule

    value = $stdin.gets.to_s.strip
    abort "empty value on stdin; nothing stored" if value.empty?
    abort "#{which} secret must be #{rule_text}; nothing stored" unless value.match?(rule)

    zone = Zone.primary
    zone.update!("#{which}_secret_ct" => value)
    AuditLog.record!("zone.#{which}_secret_set", target: zone, details: { length: value.length })
    puts "zone #{zone.name}: #{which} secret set"
  end

  desc "Print the zone authority seed for the backup runbook (CONFIRM=1 required; audited)"
  task export_authority: :environment do
    zone = Zone.primary
    abort "zone #{zone.name} has no authority imported" if zone.authority_seed_ct.blank?
    abort "This prints the zone authority SEED. Re-run with CONFIRM=1 on the host terminal only." unless ENV["CONFIRM"] == "1"

    AuditLog.record!("zone.authority_exported", target: zone, details: { pubkey_hex: zone.authority_pubkey_hex })
    puts zone.authority_seed_ct
  end
end
