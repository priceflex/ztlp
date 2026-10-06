# frozen_string_literal: true

# Active Record Encryption keys. In production the entrypoint generates them on
# first boot and persists them to the data volume (spec §9); in dev/test they
# are derived deterministically so the DB survives restarts.
keys = %w[ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY
          ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT]
if Rails.env.production? && ENV["SECRET_KEY_BASE_DUMMY"].blank?
  missing = keys.reject { |k| ENV[k].present? }
  raise "Missing #{missing.join(', ')} (bin/docker-entrypoint generates them)" if missing.any?
end
Rails.application.config.active_record.encryption.primary_key = ENV.fetch(keys[0]) { Digest::SHA256.hexdigest("#{Rails.env}-primary")[0, 32] }
Rails.application.config.active_record.encryption.deterministic_key = ENV.fetch(keys[1]) { Digest::SHA256.hexdigest("#{Rails.env}-det")[0, 32] }
Rails.application.config.active_record.encryption.key_derivation_salt = ENV.fetch(keys[2]) { Digest::SHA256.hexdigest("#{Rails.env}-salt")[0, 32] }
