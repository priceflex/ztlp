# frozen_string_literal: true

namespace :ns do
  desc "Import the NS directory (users, devices, groups of the panel zone) into the panel DB. Read-only toward the NS."
  task import: :environment do
    zone = Zone.resolve!(ENV["ZONE"])
    r = Ztlp::NsImporter.run(zone)
    if r == :not_configured
      abort "NS admin API secret is not set for #{zone.name}: run zone:set_secret[ns_admin_api] first."
    end
    puts "created: #{r[:created].map { |k, v| "#{v} #{k}" }.join(', ')}"
    puts "already present: #{r[:skipped].size}#{r[:skipped].any? ? " (#{r[:skipped].join(', ')})" : ''}"
    r[:errors].each { |e| puts "ERROR #{e}" }
    exit(1) if r[:errors].any?
  end
end
