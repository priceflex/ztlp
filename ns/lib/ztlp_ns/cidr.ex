defmodule ZtlpNs.Cidr do
  @moduledoc """
  IPv4 CIDR parser and matcher.

  Pure data; no GenServer, no application state. Used by the admin-API
  IP allow-list (item #5 of NS-Bootstrap-sync production-readiness)
  and by ZtlpNs.AdminApi.TenantRegistry.

  IPv6 is explicitly NOT supported — NS runs IPv4-only over docker
  bridges today. Future task can add IPv6 if needed.

  ## Examples

      iex> {:ok, cidr} = ZtlpNs.Cidr.parse("172.18.0.0/16")
      iex> ZtlpNs.Cidr.match?(cidr, {172, 18, 1, 5})
      true
      iex> ZtlpNs.Cidr.match?(cidr, {172, 19, 1, 5})
      false
  """

  import Bitwise

  defstruct [:base, :mask_bits, :network_int, :broadcast_int]

  @type t :: %__MODULE__{
          base: :inet.ip4_address(),
          mask_bits: 0..32,
          network_int: non_neg_integer(),
          broadcast_int: non_neg_integer()
        }

  @spec parse(binary() | nil | any()) :: {:ok, t()} | {:error, atom()}
  def parse(nil), do: {:error, :invalid_input}
  def parse(""), do: {:error, :invalid_format}

  def parse(str) when is_binary(str) do
    # IPv6 short-circuit so we give a useful error instead of :invalid_format
    if String.contains?(str, ":"), do: {:error, :ipv6_not_supported}, else: do_parse(str)
  end

  def parse(_), do: {:error, :invalid_input}

  defp do_parse(str) do
    case String.split(str, "/", parts: 2) do
      [addr_str, mask_str] ->
        with {:ok, addr} <- parse_ipv4(addr_str),
             {:ok, mask} <- parse_mask(mask_str) do
          {network_int, broadcast_int} = compute_range(addr, mask)
          base = int_to_tuple(network_int)

          {:ok,
           %__MODULE__{
             base: base,
             mask_bits: mask,
             network_int: network_int,
             broadcast_int: broadcast_int
           }}
        end

      _ ->
        {:error, :invalid_format}
    end
  end

  defp parse_ipv4(s) do
    case :inet.parse_ipv4_address(String.to_charlist(s)) do
      {:ok, ip4} -> {:ok, ip4}
      {:error, _} -> {:error, :invalid_address}
    end
  end

  defp parse_mask(s) do
    case Integer.parse(s) do
      {n, ""} when n >= 0 and n <= 32 -> {:ok, n}
      {_n, ""} -> {:error, :invalid_mask}
      _ -> {:error, :invalid_mask}
    end
  end

  defp compute_range({a, b, c, d}, mask) do
    addr_int = (a <<< 24) ||| (b <<< 16) ||| (c <<< 8) ||| d
    host_bits = 32 - mask
    mask_int = if host_bits == 32, do: 0, else: 0xFFFFFFFF <<< host_bits &&& 0xFFFFFFFF
    network_int = addr_int &&& mask_int

    broadcast_int =
      if host_bits == 0,
        do: network_int,
        else: network_int ||| ((1 <<< host_bits) - 1)

    {network_int, broadcast_int}
  end

  defp int_to_tuple(int) do
    {int >>> 24 &&& 0xFF, int >>> 16 &&& 0xFF, int >>> 8 &&& 0xFF, int &&& 0xFF}
  end

  @spec match?(t(), :inet.ip4_address()) :: boolean()
  def match?(%__MODULE__{network_int: net, broadcast_int: bcast}, {a, b, c, d})
      when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255 do
    ip_int = (a <<< 24) ||| (b <<< 16) ||| (c <<< 8) ||| d
    ip_int >= net and ip_int <= bcast
  end

  def match?(_, _), do: false
end
