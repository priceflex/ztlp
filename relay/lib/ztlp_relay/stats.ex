defmodule ZtlpRelay.Stats do
  @moduledoc """
  Pipeline statistics tracking using an Agent.

  Maintains counters for each admission pipeline layer:
  - `layer1_drops` — packets dropped at magic check
  - `layer2_drops` — packets dropped at SessionID lookup
  - `layer3_drops` — packets dropped at HeaderAuthTag verification
  - `passed` — packets that passed all three layers
  - `forwarded` — packets successfully forwarded to peers
  """

  use Agent

  @type stats :: %{
          layer1_drops: non_neg_integer(),
          layer2_drops: non_neg_integer(),
          layer3_drops: non_neg_integer(),
          passed: non_neg_integer(),
          forwarded: non_neg_integer(),
          vip_packets_processed: non_neg_integer(),
          vip_connections_started: non_neg_integer()
        }

  @doc """
  Start the stats agent.
  """
  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(_opts \\ []) do
    Agent.start_link(fn -> initial_stats() end, name: __MODULE__)
  end

  @doc """
  Get the current stats snapshot.
  """
  @spec get_stats() :: stats()
  def get_stats do
    Agent.get(__MODULE__, & &1)
  end

  @doc """
  Increment a counter by 1.
  """
  @spec increment(atom()) :: :ok
  def increment(counter)
      when counter in [:layer1_drops, :layer2_drops, :layer3_drops, :passed, :forwarded, :vip_packets_processed, :vip_connections_started] do
    Agent.update(__MODULE__, fn stats ->
      Map.update!(stats, counter, &(&1 + 1))
    end)
  end

  @doc """
  Increment a counter by a specific amount.
  """
  @spec increment(atom(), non_neg_integer()) :: :ok
  def increment(counter, amount)
      when counter in [:layer1_drops, :layer2_drops, :layer3_drops, :passed, :forwarded, :vip_packets_processed, :vip_connections_started] do
    Agent.update(__MODULE__, fn stats ->
      Map.update!(stats, counter, &(&1 + amount))
    end)
  end

  @doc """
  Reset all counters to zero.
  """
  @spec reset() :: :ok
  def reset do
    Agent.update(__MODULE__, fn _stats -> initial_stats() end)
  end

  @spec initial_stats() :: stats()
  defp initial_stats do
    %{
      layer1_drops: 0,
      layer2_drops: 0,
      layer3_drops: 0,
      passed: 0,
      forwarded: 0,
      vip_packets_processed: 0,
      vip_connections_started: 0
    }
  end
end
