defmodule ZtlpNs.RecordDefaults do
  @moduledoc """
  Canonical default TTLs and other type-specific record defaults.

  Single source of truth so the multiple registration paths
  (`ZtlpNs.Server.handle_authenticated_registration/7`,
  `ZtlpNs.Server.handle_unsigned_registration/3`, and
  `ZtlpNs.Enrollment.register_device/5`) cannot drift.

  Pre-v0.33.0 the enrollment path hardcoded `ttl: 3600` for both KEY
  and SVC records, while the regular registration path used `86_400`
  via `ZtlpNs.Server.default_ttl/1`. The mismatch meant freshly-enrolled
  client devices expired from NS after 1 hour with no auto-refresh —
  effectively unreachable-by-name on the same day they were enrolled.
  Centralising the table here prevents the drift from recurring.
  """

  @doc """
  Default TTL in seconds for a given record type.

  TTL of 0 means "never expires" (used for revocations).
  """
  @spec default_ttl(atom()) :: non_neg_integer()
  def default_ttl(:key), do: 86_400       # 24 hours
  def default_ttl(:svc), do: 86_400       # 24 hours
  def default_ttl(:relay), do: 3_600      # 1 hour — gateways re-heartbeat
  def default_ttl(:policy), do: 3_600     # 1 hour
  def default_ttl(:revoke), do: 0         # Never expires (kill-switch)
  def default_ttl(:bootstrap), do: 86_400 # 24 hours
  def default_ttl(:device), do: 86_400    # 24 hours
  def default_ttl(:user), do: 86_400      # 24 hours
  def default_ttl(:group), do: 86_400     # 24 hours
  def default_ttl(_), do: 3_600           # Default fallback for unknown types
end
