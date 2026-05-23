# frozen_string_literal: true

# An ApiClient is a trusted external system that may call the ZTLP
# Bootstrap API. The first concrete consumer is Z2LS, which calls
# `POST /api/v1/enrollment_tokens` to mint short-lived enrollment URIs
# for newly-provisioned customer devices.
#
# Authentication contract (v1, HMAC headers):
#
#   1. Caller sends X-ZTLP-Zone, X-ZTLP-Client, X-ZTLP-Timestamp,
#      X-ZTLP-Signature headers (see `Ztlp::ApiAuthenticator`).
#   2. Bootstrap looks up the ApiClient row by (zone, name).
#   3. If found AND `active`, the HMAC signature is verified against
#      the per-zone secret (same `ZTLP_HMAC_SECRET_<UPCASE_ZONE>` env
#      var the relay and gateway use).
#   4. On success, `last_used_at` is bumped via `touch_last_used!`.
#
# This model is the ALLOWLIST. The HMAC verification proves the caller
# actually holds the per-zone secret; this row says "we permit them
# to talk to the API at all." Both checks must pass.
#
# Why no `api_keys` table: Steve's brief is explicit — "Do not use a
# traditional API key model. Instead, use ZTLP-secured device-to-
# device communication." The HMAC is the credential; this row just
# carries authorization metadata (active flag, audit fields).
class ApiClient < ApplicationRecord
  validates :name, presence: true
  validates :zone, presence: true
  validates :name, uniqueness: { scope: :zone, message: "must be unique per zone" }

  scope :active, -> { where(active: true) }

  # Lookup helper for the authenticator. Returns nil on miss; lets the
  # caller render a single "unauthorized" response without leaking
  # whether the (zone, name) was unknown vs. inactive.
  def self.find_active(zone:, name:)
    return nil if zone.blank? || name.blank?

    where(zone: zone, name: name, active: true).first
  end

  # Bump `last_used_at` to mark a successful auth. Wrapped so the
  # authenticator doesn't have to know about the column.
  def touch_last_used!
    update_column(:last_used_at, Time.current)
  end
end
