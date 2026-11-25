# frozen_string_literal: true

# Fingerprint of the enrollment token's nonce (first 16 bytes of SHA-256, 32 hex). The name server
# writes the same value as `enrollment_ref` on the KEY record it creates when the token is used, so
# the pickup job finds the device whatever name the client chose (clients often append the
# computer's user name to the device name typed into the token).
class AddTokenRefToEnrollments < ActiveRecord::Migration[7.1]
  def change
    add_column :enrollments, :token_ref, :string, limit: 32
    add_index :enrollments, :token_ref, name: "idx_enrollments_token_ref"
  end
end
