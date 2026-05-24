# frozen_string_literal: true

# Phase A — Bind enrollment tokens to a principal.
#
# Adds two new columns to enrollment_tokens so the dashboard / API can
# stamp a freshly-minted token with the WHO/WHAT it's for:
#
#   * `target_kind`  — "device" | "user" | nil (legacy / unbound).
#   * `target_label` — the computer_name (when device) or the
#     username (when user). Denormalized from `ztlp_user.name` so the
#     label survives a rename of the underlying ZtlpUser row.
#
# Both columns are NULLABLE. Tokens minted before this migration keep
# working — the controller layer is what enforces presence on the
# dashboard path. Legacy BS-PR-3 API callers that only pass
# `computer_name` get backfilled to `target_kind="device"` in the
# controller; we don't bulk-rewrite existing rows.
#
# Index `[network_id, target_kind, target_label]` supports the future
# "find the active token for steve@laptop.acme.ztlp" lookup pattern on
# the dashboard token-index page and the Phase D bulk-enroll flow.
class AddTargetToEnrollmentTokens < ActiveRecord::Migration[7.1]
  def change
    add_column :enrollment_tokens, :target_kind,  :string
    add_column :enrollment_tokens, :target_label, :string
    add_index  :enrollment_tokens, [:network_id, :target_kind, :target_label],
               name: "index_enrollment_tokens_on_network_target"
  end
end
