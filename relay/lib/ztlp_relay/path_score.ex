defmodule ZtlpRelay.PathScore do
  @moduledoc """
  PathScore-based relay selection within hash ring candidates.

  Computes a composite score from per-relay metrics (RTT, packet loss,
  load factor, jitter) and selects the best relay from a candidate set.

  Score formula: `RTT_ms * (1 + loss_rate * 10) * (1 + load_factor * 2) * (1 + jitter_ms / 100)`

  Lower score = better relay. The formula heavily penalizes packet loss,
  moderately penalizes high load and jitter, while using RTT as the baseline.
  """

  @type metrics :: %{
          rtt_ms: number(),
          loss_rate: float(),
          load_factor: float(),
          jitter_ms: float()
        }

  @type scored_relay :: {binary(), number()}

  @doc """
  Compute a PathScore from relay metrics.

  Returns a numeric score (lower is better).

  Accepts metrics with or without `:jitter_ms` for backward compatibility.
  When `:jitter_ms` is absent, it defaults to 0.0.

  ## Parameters
    - `metrics` - map with `:rtt_ms` (number), `:loss_rate` (0.0-1.0),
      `:load_factor` (0.0-1.0), and optionally `:jitter_ms` (>=0.0)

  ## Examples

      iex> ZtlpRelay.PathScore.compute(%{rtt_ms: 50, loss_rate: 0.0, load_factor: 0.0, jitter_ms: 0.0})
      50.0

      iex> ZtlpRelay.PathScore.compute(%{rtt_ms: 50, loss_rate: 0.1, load_factor: 0.5, jitter_ms: 0.0})
      200.0
  """
  @spec compute(map()) :: float()
  def compute(%{rtt_ms: rtt_ms, loss_rate: loss_rate, load_factor: load_factor} = metrics) do
    jitter_ms = Map.get(metrics, :jitter_ms, 0.0)
    rtt_ms * (1.0 + loss_rate * 10.0) * (1.0 + load_factor * 2.0) * (1.0 + jitter_ms / 100.0)
  end

  @doc """
  Select the best relay from hash ring candidates using PathScore.

  `candidates` is a list of node_info maps (from HashRing.get_nodes/3).
  `scores` is a map of `node_id => metrics()`.

  Returns `{:ok, best_node_info}` or `:error` if no candidates have scores.
  Relays without scores are skipped (considered unreachable).
  """
  @spec select_best([map()], %{binary() => metrics()}) :: {:ok, map()} | :error
  def select_best([], _scores), do: :error

  def select_best(candidates, scores) when is_list(candidates) and is_map(scores) do
    scored =
      candidates
      |> Enum.flat_map(fn candidate ->
        case Map.get(scores, candidate.node_id) do
          nil -> []
          metrics -> [{candidate, compute(metrics)}]
        end
      end)

    case scored do
      [] ->
        :error

      list ->
        {best, _score} = Enum.min_by(list, fn {_candidate, score} -> score end)
        {:ok, best}
    end
  end

  @doc """
  Update RTT using exponential moving average.

  Alpha controls smoothing: higher alpha = more weight on new sample.
  Default alpha: 0.3 (30% new, 70% old).
  """
  @spec update_rtt(number(), number(), float()) :: float()
  def update_rtt(current_rtt, new_sample, alpha \\ 0.3) do
    alpha * new_sample + (1.0 - alpha) * current_rtt
  end

  @doc """
  Compute load factor from active and max session counts.

  Returns a float between 0.0 and 1.0.
  """
  @spec compute_load_factor(non_neg_integer(), pos_integer()) :: float()
  def compute_load_factor(_active, max) when max <= 0, do: 1.0
  def compute_load_factor(active, max), do: min(active / max, 1.0)

  @doc """
  Compute jitter (standard deviation) from a list of RTT samples.

  Returns 0.0 if fewer than 2 samples are provided.

  ## Examples

      iex> ZtlpRelay.PathScore.compute_jitter([50.0, 50.0, 50.0])
      0.0

      iex> ZtlpRelay.PathScore.compute_jitter([40.0, 60.0])
      10.0
  """
  @spec compute_jitter([number()]) :: float()
  def compute_jitter([]), do: 0.0
  def compute_jitter([_]), do: 0.0

  def compute_jitter(samples) when is_list(samples) do
    n = length(samples)
    mean = Enum.sum(samples) / n
    variance = Enum.reduce(samples, 0.0, fn s, acc -> acc + (s - mean) * (s - mean) end) / n
    :math.sqrt(variance)
  end
end
