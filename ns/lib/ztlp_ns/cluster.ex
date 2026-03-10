defmodule ZtlpNs.Cluster do
  @moduledoc """
  Multi-node Mnesia cluster management for ZTLP-NS federation.

  Provides functions to join/leave a cluster of NS nodes,
  with automatic table replication.

  NOT YET IMPLEMENTED — stubs for future federation work.
  """

  @doc "Join an existing NS cluster node. Replicates all tables."
  @spec join(node()) :: {:error, :not_implemented}
  def join(_node_name), do: {:error, :not_implemented}

  @doc "Leave the cluster gracefully."
  @spec leave() :: {:error, :not_implemented}
  def leave(), do: {:error, :not_implemented}

  @doc "List all nodes in the current Mnesia cluster."
  @spec members() :: [node()]
  def members(), do: [node()]

  @doc "Check if this node is part of a multi-node cluster."
  @spec clustered?() :: boolean()
  def clustered?(), do: length(members()) > 1
end
