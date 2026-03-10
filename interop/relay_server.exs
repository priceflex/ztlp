#!/usr/bin/env elixir
#
# ZTLP Interop Test — Elixir Relay Server
#
# Starts the relay, accepts session registrations via stdin.
#
# Protocol (stdin, line-based):
#   REGISTER <session_id_hex> <port_a> <port_b>
#     → Registers session with peers at 127.0.0.1:port_a and 127.0.0.1:port_b
#     ← Prints "OK <session_id_hex>" to stdout
#   QUIT → exits
#
# On startup, prints "READY <port>" to stdout.

# Add compiled relay beam files to the code path
relay_dir = Path.expand("../relay", __DIR__)
build_dir = Path.join(relay_dir, "_build/dev/lib/ztlp_relay/ebin")

unless File.dir?(build_dir) do
  IO.puts(:stderr, "ERROR: relay not compiled. Run 'cd relay && mix compile' first.")
  System.halt(1)
end

Code.prepend_path(build_dir)

# Start required OTP apps
{:ok, _} = Application.ensure_all_started(:crypto)

# Start the relay components manually
{:ok, _} = ZtlpRelay.Stats.start_link([])
{:ok, _} = ZtlpRelay.SessionRegistry.start_link([])
{:ok, _} = DynamicSupervisor.start_link(name: ZtlpRelay.SessionSupervisor, strategy: :one_for_one)

# Start UDP listener on random port
Application.put_env(:ztlp_relay, :listen_port, 0)
{:ok, _} = ZtlpRelay.UdpListener.start_link([])

port = ZtlpRelay.UdpListener.get_port()

# Signal readiness (flush immediately)
IO.puts("READY #{port}")

# Command loop — read from stdin
defmodule CommandLoop do
  def run do
    case IO.gets("") do
      :eof ->
        # stdin closed, keep running until killed
        Process.sleep(:infinity)

      {:error, _} ->
        Process.sleep(:infinity)

      line when is_binary(line) ->
        line = String.trim(line)
        handle(line)
        run()
    end
  end

  defp handle("REGISTER " <> rest) do
    case String.split(rest) do
      [session_id_hex, port_a_str, port_b_str] ->
        case Base.decode16(String.upcase(session_id_hex)) do
          {:ok, session_id} ->
            {port_a, _} = Integer.parse(port_a_str)
            {port_b, _} = Integer.parse(port_b_str)

            peer_a = {{127, 0, 0, 1}, port_a}
            peer_b = {{127, 0, 0, 1}, port_b}

            ZtlpRelay.SessionRegistry.register_session(session_id, peer_a, peer_b)

            {:ok, pid} = ZtlpRelay.SessionSupervisor.start_session(
              session_id: session_id,
              peer_a: peer_a,
              peer_b: peer_b,
              timeout_ms: 30_000
            )
            ZtlpRelay.SessionRegistry.update_session_pid(session_id, pid)

            IO.puts("OK #{session_id_hex}")

          :error ->
            IO.puts("ERR invalid hex")
        end

      _ ->
        IO.puts("ERR bad REGISTER syntax")
    end
  end

  defp handle("QUIT") do
    IO.puts("BYE")
    System.halt(0)
  end

  defp handle("") do
    :ok
  end

  defp handle(other) do
    IO.puts("ERR unknown: #{other}")
  end
end

CommandLoop.run()
