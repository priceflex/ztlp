defmodule ZtlpGateway.HandshakeTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.{Crypto, Handshake}

  # Helper: generate a static keypair for one side
  defp make_keypair, do: Crypto.generate_keypair()

  describe "full Noise_XX handshake" do
    test "initiator and responder derive the same transport keys" do
      {i_pub, i_priv} = make_keypair()
      {r_pub, r_priv} = make_keypair()

      initiator = Handshake.init_initiator(i_pub, i_priv)
      responder = Handshake.init_responder(r_pub, r_priv)

      # Message 1: initiator → responder (→ e)
      {initiator, msg1} = Handshake.create_msg1(initiator)
      {responder, _} = Handshake.handle_msg1(responder, msg1)

      # Message 2: responder → initiator (← e, ee, s, es)
      {responder, msg2} = Handshake.create_msg2(responder)
      {initiator, _payload} = Handshake.process_msg2(initiator, msg2)

      # Message 3: initiator → responder (→ s, se)
      {initiator, msg3} = Handshake.create_msg3(initiator)
      {responder, _payload} = Handshake.handle_msg3(responder, msg3)

      # Both sides should be complete
      assert initiator.phase == :complete
      assert responder.phase == :complete

      # Derive transport keys
      {:ok, i_keys} = Handshake.split(initiator)
      {:ok, r_keys} = Handshake.split(responder)

      # Initiator's i2r == Responder's i2r (same key for same direction)
      assert i_keys.i2r_key == r_keys.i2r_key
      assert i_keys.r2i_key == r_keys.r2i_key

      # But the two directions are different keys
      assert i_keys.i2r_key != i_keys.r2i_key
    end

    test "responder learns initiator's static key" do
      {i_pub, i_priv} = make_keypair()
      {r_pub, r_priv} = make_keypair()

      initiator = Handshake.init_initiator(i_pub, i_priv)
      responder = Handshake.init_responder(r_pub, r_priv)

      {initiator, msg1} = Handshake.create_msg1(initiator)
      {responder, _} = Handshake.handle_msg1(responder, msg1)
      {responder, msg2} = Handshake.create_msg2(responder)
      {initiator, _} = Handshake.process_msg2(initiator, msg2)
      {initiator, msg3} = Handshake.create_msg3(initiator)
      {responder, _} = Handshake.handle_msg3(responder, msg3)

      # Responder should know initiator's static key
      assert responder.rs == i_pub
      # Initiator should know responder's static key
      assert initiator.rs == r_pub
    end

    test "handshake with payload in msg3" do
      {i_pub, i_priv} = make_keypair()
      {r_pub, r_priv} = make_keypair()

      initiator = Handshake.init_initiator(i_pub, i_priv)
      responder = Handshake.init_responder(r_pub, r_priv)

      {initiator, msg1} = Handshake.create_msg1(initiator)
      {responder, _} = Handshake.handle_msg1(responder, msg1)
      {responder, msg2} = Handshake.create_msg2(responder)
      {initiator, _} = Handshake.process_msg2(initiator, msg2)

      # Include a payload in message 3
      payload = "initial data from initiator"
      {_initiator, msg3} = Handshake.create_msg3(initiator, payload)
      {_responder, received_payload} = Handshake.handle_msg3(responder, msg3)

      assert received_payload == payload
    end

    test "transport keys encrypt/decrypt correctly" do
      {i_pub, i_priv} = make_keypair()
      {r_pub, r_priv} = make_keypair()

      # Full handshake
      initiator = Handshake.init_initiator(i_pub, i_priv)
      responder = Handshake.init_responder(r_pub, r_priv)

      {initiator, msg1} = Handshake.create_msg1(initiator)
      {responder, _} = Handshake.handle_msg1(responder, msg1)
      {responder, msg2} = Handshake.create_msg2(responder)
      {initiator, _} = Handshake.process_msg2(initiator, msg2)
      {initiator, msg3} = Handshake.create_msg3(initiator)
      {responder, _} = Handshake.handle_msg3(responder, msg3)

      {:ok, i_keys} = Handshake.split(initiator)
      {:ok, r_keys} = Handshake.split(responder)

      # Initiator encrypts with i2r_key, responder decrypts with i2r_key
      nonce = <<0::32, 1::little-64>>
      {ct, tag} = Crypto.encrypt(i_keys.i2r_key, nonce, "hello from client", "")
      assert Crypto.decrypt(r_keys.i2r_key, nonce, ct, "", tag) == "hello from client"

      # Responder encrypts with r2i_key, initiator decrypts with r2i_key
      {ct2, tag2} = Crypto.encrypt(r_keys.r2i_key, nonce, "hello from gateway", "")
      assert Crypto.decrypt(i_keys.r2i_key, nonce, ct2, "", tag2) == "hello from gateway"
    end

    test "split fails if handshake not complete" do
      {pub, priv} = make_keypair()
      state = Handshake.init_responder(pub, priv)
      assert Handshake.split(state) == {:error, :handshake_incomplete}
    end
  end

  describe "error handling" do
    test "msg1 too short" do
      {pub, priv} = make_keypair()
      responder = Handshake.init_responder(pub, priv)
      assert {:error, :msg1_too_short} = Handshake.handle_msg1(responder, <<1, 2, 3>>)
    end

    test "msg3 too short" do
      {i_pub, i_priv} = make_keypair()
      {r_pub, r_priv} = make_keypair()

      initiator = Handshake.init_initiator(i_pub, i_priv)
      responder = Handshake.init_responder(r_pub, r_priv)

      {initiator, msg1} = Handshake.create_msg1(initiator)
      {responder, _} = Handshake.handle_msg1(responder, msg1)
      {responder, msg2} = Handshake.create_msg2(responder)
      {_initiator, _} = Handshake.process_msg2(initiator, msg2)

      # Short msg3
      assert {:error, :msg3_too_short} = Handshake.handle_msg3(responder, <<1, 2, 3>>)
    end

    test "msg3 with tampered static key" do
      {i_pub, i_priv} = make_keypair()
      {r_pub, r_priv} = make_keypair()

      initiator = Handshake.init_initiator(i_pub, i_priv)
      responder = Handshake.init_responder(r_pub, r_priv)

      {initiator, msg1} = Handshake.create_msg1(initiator)
      {responder, _} = Handshake.handle_msg1(responder, msg1)
      {responder, msg2} = Handshake.create_msg2(responder)
      {initiator, _} = Handshake.process_msg2(initiator, msg2)

      {_initiator, msg3} = Handshake.create_msg3(initiator)

      # Tamper with the encrypted static key (first 48 bytes)
      <<first::8, rest::binary>> = msg3
      tampered = <<Bitwise.bxor(first, 0xFF)::8, rest::binary>>
      assert {:error, :decrypt_static_failed} = Handshake.handle_msg3(responder, tampered)
    end

    test "multiple handshakes produce different keys" do
      {i_pub, i_priv} = make_keypair()
      {r_pub, r_priv} = make_keypair()

      # First handshake
      i1 = Handshake.init_initiator(i_pub, i_priv)
      r1 = Handshake.init_responder(r_pub, r_priv)
      {i1, m1} = Handshake.create_msg1(i1)
      {r1, _} = Handshake.handle_msg1(r1, m1)
      {r1, m2} = Handshake.create_msg2(r1)
      {i1, _} = Handshake.process_msg2(i1, m2)
      {_i1, m3} = Handshake.create_msg3(i1)
      {r1, _} = Handshake.handle_msg3(r1, m3)
      {:ok, keys1} = Handshake.split(r1)

      # Second handshake (same static keys, different ephemeral)
      i2 = Handshake.init_initiator(i_pub, i_priv)
      r2 = Handshake.init_responder(r_pub, r_priv)
      {i2, m1b} = Handshake.create_msg1(i2)
      {r2, _} = Handshake.handle_msg1(r2, m1b)
      {r2, m2b} = Handshake.create_msg2(r2)
      {i2, _} = Handshake.process_msg2(i2, m2b)
      {_i2, m3b} = Handshake.create_msg3(i2)
      {r2, _} = Handshake.handle_msg3(r2, m3b)
      {:ok, keys2} = Handshake.split(r2)

      # Different ephemeral keys → different transport keys (PFS)
      assert keys1.i2r_key != keys2.i2r_key
      assert keys1.r2i_key != keys2.r2i_key
    end
  end
end
