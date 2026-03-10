defmodule ZtlpRelay.IngressTest do
  use ExUnit.Case

  alias ZtlpRelay.{Ingress, AdmissionToken, Packet, RateLimiter}

  @table :ztlp_ingress_test_rate_limiter
  @secret AdmissionToken.generate_secret()
  @issuer_id :crypto.strong_rand_bytes(16)

  setup do
    # Start a dedicated rate limiter for ingress tests
    name = :"ingress_rl_#{:erlang.unique_integer([:positive])}"
    {:ok, pid} = RateLimiter.start_link(
      name: name,
      table: @table,
      cleanup_interval_ms: 60_000
    )

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
    end)

    state = Ingress.new_state(rate_limiter_table: @table)
    {:ok, state: state}
  end

  defp make_hello(opts \\ []) do
    src_node_id = Keyword.get(opts, :src_node_id, :crypto.strong_rand_bytes(16))
    session_id = Keyword.get(opts, :session_id, :crypto.strong_rand_bytes(12))

    Packet.build_handshake(:hello, session_id,
      src_node_id: src_node_id
    )
  end

  defp default_opts do
    [
      secret_key: @secret,
      issuer_id: @issuer_id,
      ttl_seconds: 300,
      session_count: 0,
      max_sessions: 10_000,
      sac_threshold: 0.7
    ]
  end

  describe "handle_hello/4 happy path" do
    test "admits a valid HELLO and returns a RAT", %{state: state} do
      hello = make_hello()
      sender = {{127, 0, 0, 1}, 5000}

      assert {:ok, :admitted, rat} = Ingress.handle_hello(hello, sender, state, default_opts())
      assert byte_size(rat) == 93

      # Verify the RAT is valid
      assert {:ok, fields} = AdmissionToken.verify(rat, @secret)
      assert fields.node_id == hello.src_node_id
      assert fields.issuer_id == @issuer_id
    end

    test "RAT session_scope matches the HELLO session_id", %{state: state} do
      session_id = :crypto.strong_rand_bytes(12)
      hello = make_hello(session_id: session_id)
      sender = {{127, 0, 0, 1}, 5000}

      {:ok, :admitted, rat} = Ingress.handle_hello(hello, sender, state, default_opts())
      {:ok, fields} = AdmissionToken.verify(rat, @secret)

      assert fields.session_scope == session_id
    end

    test "rejects non-HELLO packets", %{state: state} do
      data_pkt = Packet.build_handshake(:hello_ack, :crypto.strong_rand_bytes(12))
      sender = {{127, 0, 0, 1}, 5000}

      assert {:error, :not_hello} = Ingress.handle_hello(data_pkt, sender, state, default_opts())
    end
  end

  describe "rate limiting" do
    test "enforces per-IP rate limit", %{state: state} do
      sender = {{10, 0, 0, 1}, 5000}
      opts = Keyword.merge(default_opts(), ip_limit: 2)

      hello1 = make_hello()
      hello2 = make_hello()
      hello3 = make_hello()

      assert {:ok, :admitted, _} = Ingress.handle_hello(hello1, sender, state, opts)
      assert {:ok, :admitted, _} = Ingress.handle_hello(hello2, sender, state, opts)
      assert {:error, :ip_rate_limited} = Ingress.handle_hello(hello3, sender, state, opts)
    end

    test "enforces per-NodeID rate limit", %{state: state} do
      node_id = :crypto.strong_rand_bytes(16)
      opts = Keyword.merge(default_opts(), node_limit: 1)

      # Different IPs, same NodeID
      sender1 = {{10, 0, 0, 1}, 5000}
      sender2 = {{10, 0, 0, 2}, 5000}

      hello1 = make_hello(src_node_id: node_id)
      hello2 = make_hello(src_node_id: node_id)

      assert {:ok, :admitted, _} = Ingress.handle_hello(hello1, sender1, state, opts)
      assert {:error, :node_rate_limited} = Ingress.handle_hello(hello2, sender2, state, opts)
    end

    test "different IPs have independent rate limits", %{state: state} do
      opts = Keyword.merge(default_opts(), ip_limit: 1)

      sender_a = {{10, 0, 0, 1}, 5000}
      sender_b = {{10, 0, 0, 2}, 5000}

      hello_a = make_hello()
      hello_b = make_hello()

      assert {:ok, :admitted, _} = Ingress.handle_hello(hello_a, sender_a, state, opts)
      assert {:ok, :admitted, _} = Ingress.handle_hello(hello_b, sender_b, state, opts)
    end
  end

  describe "Stateless Admission Challenge" do
    test "issues challenge when load exceeds threshold", %{state: state} do
      # 8000 sessions / 10000 max = 0.8 > 0.7 threshold
      opts = Keyword.merge(default_opts(), session_count: 8000, max_sessions: 10_000)

      hello = make_hello()
      sender = {{127, 0, 0, 1}, 5000}

      assert {:challenge, challenge} = Ingress.handle_hello(hello, sender, state, opts)
      assert byte_size(challenge) == 32
    end

    test "admits when load is below threshold", %{state: state} do
      # 5000 / 10000 = 0.5 < 0.7 threshold
      opts = Keyword.merge(default_opts(), session_count: 5000, max_sessions: 10_000)

      hello = make_hello()
      sender = {{127, 0, 0, 1}, 5000}

      assert {:ok, :admitted, _rat} = Ingress.handle_hello(hello, sender, state, opts)
    end

    test "admits with valid challenge response", %{state: state} do
      sender = {{127, 0, 0, 1}, 5000}
      opts = Keyword.merge(default_opts(), session_count: 8000, max_sessions: 10_000)

      # First: get the challenge
      hello = make_hello()
      {:challenge, challenge} = Ingress.handle_hello(hello, sender, state, opts)

      # Second: respond with the challenge
      opts_with_response = Keyword.put(opts, :challenge_response, challenge)
      hello2 = make_hello()
      assert {:ok, :admitted, _rat} = Ingress.handle_hello(hello2, sender, state, opts_with_response)
    end

    test "rejects with invalid challenge response", %{state: state} do
      sender = {{127, 0, 0, 1}, 5000}
      opts = Keyword.merge(default_opts(),
        session_count: 8000,
        max_sessions: 10_000,
        challenge_response: :crypto.strong_rand_bytes(32)
      )

      hello = make_hello()
      assert {:error, :invalid_challenge} = Ingress.handle_hello(hello, sender, state, opts)
    end
  end

  describe "generate_challenge/2 and verify_challenge/3" do
    test "generates and verifies a challenge" do
      sender = {{127, 0, 0, 1}, 5000}
      opts = [secret_key: @secret]

      challenge = Ingress.generate_challenge(sender, opts)
      assert byte_size(challenge) == 32

      assert Ingress.verify_challenge(challenge, sender, opts) == true
    end

    test "challenge is deterministic for same window" do
      sender = {{127, 0, 0, 1}, 5000}
      opts = [secret_key: @secret, window_seconds: 60]

      c1 = Ingress.generate_challenge(sender, opts)
      c2 = Ingress.generate_challenge(sender, opts)
      assert c1 == c2
    end

    test "challenge differs for different senders" do
      opts = [secret_key: @secret]
      sender_a = {{127, 0, 0, 1}, 5000}
      sender_b = {{127, 0, 0, 2}, 5000}

      c1 = Ingress.generate_challenge(sender_a, opts)
      c2 = Ingress.generate_challenge(sender_b, opts)
      assert c1 != c2
    end

    test "challenge differs for different ports" do
      opts = [secret_key: @secret]
      sender_a = {{127, 0, 0, 1}, 5000}
      sender_b = {{127, 0, 0, 1}, 5001}

      c1 = Ingress.generate_challenge(sender_a, opts)
      c2 = Ingress.generate_challenge(sender_b, opts)
      assert c1 != c2
    end

    test "rejects challenge for wrong sender" do
      opts = [secret_key: @secret]
      sender_a = {{127, 0, 0, 1}, 5000}
      sender_b = {{127, 0, 0, 2}, 5000}

      challenge = Ingress.generate_challenge(sender_a, opts)
      assert Ingress.verify_challenge(challenge, sender_b, opts) == false
    end

    test "rejects random bytes as challenge" do
      sender = {{127, 0, 0, 1}, 5000}
      opts = [secret_key: @secret]

      fake = :crypto.strong_rand_bytes(32)
      assert Ingress.verify_challenge(fake, sender, opts) == false
    end
  end

  describe "invalid HELLO handling" do
    test "rejects compact data packet", %{state: state} do
      pkt = Packet.build_data(:crypto.strong_rand_bytes(12), 0)
      sender = {{127, 0, 0, 1}, 5000}

      assert {:error, :not_hello} = Ingress.handle_hello(pkt, sender, state, default_opts())
    end

    test "rejects CLOSE packet", %{state: state} do
      pkt = Packet.build_handshake(:close, :crypto.strong_rand_bytes(12))
      sender = {{127, 0, 0, 1}, 5000}

      assert {:error, :not_hello} = Ingress.handle_hello(pkt, sender, state, default_opts())
    end
  end
end
