defmodule ZtlpNs.Store.Migration do
  @moduledoc """
  Data migration utilities for the ZTLP-NS record store.

  Provides helpers for migrating data from the old ETS-backed store
  (v1) to the current Mnesia-backed store. This is a manual utility —
  it is NOT auto-run on startup.

  ## Usage

      # If you have records from the old ETS store (e.g., from a backup script):
      records = [%ZtlpNs.Record{...}, ...]
      {:ok, count} = ZtlpNs.Store.Migration.v1_to_mnesia(records)
  """

  alias ZtlpNs.Record

  @records_table :ztlp_ns_records
  @revoked_table :ztlp_ns_revoked

  @doc """
  Bulk-insert a list of records into Mnesia.

  Intended for migrating from the old ETS-backed store. Records are
  inserted inside a single Mnesia transaction for atomicity.

  Revocation records automatically populate the revocation table.

  Returns `{:ok, count}` on success or `{:error, reason}` on failure.
  """
  @spec v1_to_mnesia([Record.t()]) :: {:ok, non_neg_integer()} | {:error, term()}
  def v1_to_mnesia(records) when is_list(records) do
    result =
      :mnesia.transaction(fn ->
        Enum.each(records, fn %Record{} = record ->
          :mnesia.write({@records_table, {record.name, record.type}, record})

          if record.type == :revoke do
            revoked_ids = Map.get(record.data, :revoked_ids, [])

            Enum.each(revoked_ids, fn id ->
              :mnesia.write({@revoked_table, id, record})
            end)
          end
        end)
      end)

    case result do
      {:atomic, :ok} -> {:ok, length(records)}
      {:aborted, reason} -> {:error, reason}
    end
  end
end
