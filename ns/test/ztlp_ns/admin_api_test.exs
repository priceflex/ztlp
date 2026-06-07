defmodule ZtlpNs.AdminApiTest do
  # async: false — `describe "list_records/1"` mutates the shared Mnesia
  # Store via `Store.clear/0` + inserts; can't run concurrently with
  # other Store-touching tests.
  use ExUnit.Case, async: false
  alias ZtlpNs.AdminApi

  @secret <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32>>

  describe "verify_request/4" do
    test "returns :ok for a valid signature within the time window" do
      ts = System.system_time(:second)
      canonical = "GET\n/admin/records\n#{ts}\n#{:crypto.hash(:sha256, "") |> Base.encode16(case: :lower)}"
      sig = :crypto.mac(:hmac, :sha256, @secret, canonical) |> Base.encode16(case: :lower)
      headers = %{"x-ns-timestamp" => to_string(ts), "x-ns-signature" => sig}
      assert :ok = AdminApi.verify_request("GET", "/admin/records", "", headers, secret: @secret)
    end

    test "returns {:error, :bad_signature} for a tampered signature" do
      ts = System.system_time(:second)
      headers = %{"x-ns-timestamp" => to_string(ts), "x-ns-signature" => String.duplicate("0", 64)}
      assert {:error, :bad_signature} = AdminApi.verify_request("GET", "/admin/records", "", headers, secret: @secret)
    end

    test "returns {:error, :stale_timestamp} for a timestamp older than 300s" do
      ts = System.system_time(:second) - 400
      canonical = "GET\n/admin/records\n#{ts}\n#{:crypto.hash(:sha256, "") |> Base.encode16(case: :lower)}"
      sig = :crypto.mac(:hmac, :sha256, @secret, canonical) |> Base.encode16(case: :lower)
      headers = %{"x-ns-timestamp" => to_string(ts), "x-ns-signature" => sig}
      assert {:error, :stale_timestamp} = AdminApi.verify_request("GET", "/admin/records", "", headers, secret: @secret)
    end

    test "returns {:error, :missing_header} when timestamp absent" do
      assert {:error, :missing_header} = AdminApi.verify_request("GET", "/admin/records", "", %{"x-ns-signature" => "abc"}, secret: @secret)
    end

    test "returns {:error, :missing_header} when signature absent" do
      assert {:error, :missing_header} = AdminApi.verify_request("GET", "/admin/records", "", %{"x-ns-timestamp" => "0"}, secret: @secret)
    end

    test "returns {:error, :no_secret} when secret is nil" do
      assert {:error, :no_secret} = AdminApi.verify_request("GET", "/admin/records", "", %{}, secret: nil)
    end

    test "signature is computed over the FULL path including query string" do
      ts = System.system_time(:second)
      path = "/admin/records?zone=trs.ztlp&type=key"
      canonical = "GET\n#{path}\n#{ts}\n#{:crypto.hash(:sha256, "") |> Base.encode16(case: :lower)}"
      sig = :crypto.mac(:hmac, :sha256, @secret, canonical) |> Base.encode16(case: :lower)
      headers = %{"x-ns-timestamp" => to_string(ts), "x-ns-signature" => sig}
      assert :ok = AdminApi.verify_request("GET", path, "", headers, secret: @secret)
      # Same signature against a different path must FAIL
      assert {:error, :bad_signature} = AdminApi.verify_request("GET", "/admin/records", "", headers, secret: @secret)
    end
  end

  describe "verify_request_with_registry/6" do
    setup do
      trs_secret = :crypto.strong_rand_bytes(32)
      acme_secret = :crypto.strong_rand_bytes(32)
      global_secret = :crypto.strong_rand_bytes(32)

      trs = %ZtlpNs.AdminApi.TenantRegistry{
        slug: "TRS",
        secret: trs_secret,
        zone_glob: "*.trs.ztlp",
        cidrs: []
      }

      acme = %ZtlpNs.AdminApi.TenantRegistry{
        slug: "ACME",
        secret: acme_secret,
        zone_glob: "*.acme.ztlp",
        cidrs: []
      }

      %{
        registry: %{"TRS" => trs, "ACME" => acme},
        trs_secret: trs_secret,
        acme_secret: acme_secret,
        global_secret: global_secret,
        trs: trs,
        acme: acme
      }
    end

    test "two tenants, signed by TRS — returns {:ok, {:tenant, TRS}}", ctx do
      headers = build_signed_headers("GET", "/admin/records", "", ctx.trs_secret)
      assert {:ok, {:tenant, %{slug: "TRS"}}} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, ctx.registry, ctx.global_secret
               )
    end

    test "two tenants, signed by ACME — returns {:ok, {:tenant, ACME}}", ctx do
      headers = build_signed_headers("GET", "/admin/records", "", ctx.acme_secret)
      assert {:ok, {:tenant, %{slug: "ACME"}}} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, ctx.registry, ctx.global_secret
               )
    end

    test "two tenants, signed by random secret — returns {:error, :bad_signature}", ctx do
      random = :crypto.strong_rand_bytes(32)
      headers = build_signed_headers("GET", "/admin/records", "", random)
      assert {:error, :bad_signature} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, ctx.registry, ctx.global_secret
               )
    end

    test "two tenants + global, signed by global — returns {:ok, :legacy}", ctx do
      headers = build_signed_headers("GET", "/admin/records", "", ctx.global_secret)
      assert {:ok, :legacy} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, ctx.registry, ctx.global_secret
               )
    end

    test "two tenants + global, signed by tenant — TENANT WINS (not legacy)", ctx do
      headers = build_signed_headers("GET", "/admin/records", "", ctx.trs_secret)
      assert {:ok, {:tenant, %{slug: "TRS"}}} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, ctx.registry, ctx.global_secret
               )
    end

    test "no tenants + global, signed by global — returns {:ok, :legacy}", ctx do
      headers = build_signed_headers("GET", "/admin/records", "", ctx.global_secret)
      assert {:ok, :legacy} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, %{}, ctx.global_secret
               )
    end

    test "no tenants + no global — returns {:error, :no_secret}", ctx do
      headers = build_signed_headers("GET", "/admin/records", "", ctx.global_secret)
      assert {:error, :no_secret} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, %{}, nil)
    end

    test "tenants + no global, signed by random — returns {:error, :bad_signature}", ctx do
      random = :crypto.strong_rand_bytes(32)
      headers = build_signed_headers("GET", "/admin/records", "", random)
      assert {:error, :bad_signature} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, ctx.registry, nil)
    end

    test "stale timestamp rejected regardless of tenant", ctx do
      stale_ts = System.system_time(:second) - 1000
      body_hash = :crypto.hash(:sha256, "") |> Base.encode16(case: :lower)
      canonical = "GET\n/admin/records\n#{stale_ts}\n#{body_hash}"
      sig = :crypto.mac(:hmac, :sha256, ctx.trs_secret, canonical) |> Base.encode16(case: :lower)
      headers = %{"x-ns-timestamp" => to_string(stale_ts), "x-ns-signature" => sig}
      assert {:error, :stale_timestamp} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, ctx.registry, ctx.global_secret
               )
    end

    test "missing timestamp header → {:error, :missing_header}", ctx do
      headers = %{"x-ns-signature" => String.duplicate("0", 64)}
      assert {:error, :missing_header} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, ctx.registry, ctx.global_secret
               )
    end

    test "missing signature header → {:error, :missing_header}", ctx do
      headers = %{"x-ns-timestamp" => to_string(System.system_time(:second))}
      assert {:error, :missing_header} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, ctx.registry, ctx.global_secret
               )
    end

    test "malformed timestamp → {:error, :bad_request}", ctx do
      headers = %{
        "x-ns-timestamp" => "not-a-number",
        "x-ns-signature" => String.duplicate("0", 64)
      }
      assert {:error, :bad_request} =
               AdminApi.verify_request_with_registry(
                 "GET", "/admin/records", "", headers, ctx.registry, ctx.global_secret
               )
    end
  end

  # Helper used by verify_request_with_registry/6 describe block.
  defp build_signed_headers(method, path, body, secret) do
    ts = System.system_time(:second)
    body_hash = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)
    canonical = "#{method}\n#{path}\n#{ts}\n#{body_hash}"
    sig = :crypto.mac(:hmac, :sha256, secret, canonical) |> Base.encode16(case: :lower)
    %{"x-ns-timestamp" => to_string(ts), "x-ns-signature" => sig}
  end

  describe "list_records/1" do
    alias ZtlpNs.{Crypto, Record, Store}

    setup do
      # Reset the shared Mnesia store, then insert two records with different
      # types and zones. We hand-build %Record{} structs (rather than using
      # Record.new_key/4) so we can place a raw-binary `:pubkey` in `data`
      # — that exercises the projection's pubkey_hex branch.
      #
      # Several other test files (admin_test, anti_entropy_test, etc.) tear
      # down Mnesia and the :ztlp_ns app in their on_exit hooks. If this
      # describe block runs after one of those, Store.clear/0 would fail
      # with `{:node_not_running, :nonode@nohost}`. Ensure both apps are up
      # before clearing.
      Application.ensure_all_started(:mnesia)
      Application.ensure_all_started(:ztlp_ns)
      Store.clear()

      {pub_a, priv_a} = Crypto.generate_keypair()
      {_pub_b, priv_b} = Crypto.generate_keypair()
      now = System.system_time(:second)

      rec_a =
        %Record{
          name: "trsdc.tech-rockstars.trs.ztlp",
          type: :key,
          data: %{pubkey: pub_a},
          created_at: now,
          ttl: 86_400,
          serial: 3
        }
        |> Record.sign(priv_a)

      rec_b =
        %Record{
          name: "dan.adms.trs.ztlp",
          type: :svc,
          data: %{port: 22},
          created_at: now,
          ttl: 86_400,
          serial: 1
        }
        |> Record.sign(priv_b)

      :ok = Store.insert(rec_a)
      :ok = Store.insert(rec_b)

      %{rec_a: rec_a, rec_b: rec_b}
    end

    test "returns every non-expired record as a JSON-safe map", %{rec_a: rec_a, rec_b: rec_b} do
      result = AdminApi.list_records([])
      assert result.count == 2
      names = result.records |> Enum.map(& &1.name) |> Enum.sort()
      assert names == Enum.sort([rec_a.name, rec_b.name])
    end

    test "filters by zone suffix" do
      result = AdminApi.list_records(zone: "tech-rockstars.trs.ztlp")
      assert result.count == 1
      assert hd(result.records).name == "trsdc.tech-rockstars.trs.ztlp"
    end

    test "filters by type" do
      result = AdminApi.list_records(type: :svc)
      assert result.count == 1
      assert hd(result.records).type == "svc"
    end

    test "projection MUST NOT include raw signature bytes" do
      result = AdminApi.list_records([])

      Enum.each(result.records, fn rec ->
        refute Map.has_key?(rec, :signature)
        refute Map.has_key?(rec, "signature")
        refute Map.has_key?(rec, :signer_public_key)
      end)
    end

    test "type field is serialized as a string, not an atom" do
      result = AdminApi.list_records([])
      Enum.each(result.records, fn rec -> assert is_binary(rec.type) end)
    end

    test "result is JSON-safe (no signature/key material, type is a string)" do
      # ZtlpNs has a deliberate zero-deps stance (no Jason). Instead of
      # round-tripping through an encoder, we recursively walk the
      # projection and assert it contains ONLY primitive-safe values:
      # binaries that are valid UTF-8, integers, floats, atoms, and
      # maps/lists of the same. Raw signature bytes would be a non-UTF-8
      # binary and would trip this check — that's the point.
      result = AdminApi.list_records([])
      assert json_safe?(result), "projection contains a non-JSON-safe value"
    end

    test "pubkey is rendered as lowercase hex when data.pubkey is a raw binary" do
      result = AdminApi.list_records(type: :key)
      rec = hd(result.records)
      assert is_binary(rec.pubkey_hex)
      assert String.match?(rec.pubkey_hex, ~r/^[0-9a-f]+$/)
    end
  end

  # ── helpers ──────────────────────────────────────────────────────────

  # Recursively walks a value and returns true iff it contains only
  # JSON-encodable primitives. A binary qualifies only if it's valid
  # UTF-8 — raw signature bytes (64 random bytes) will fail UTF-8
  # validation and trip this check.
  defp json_safe?(v) when is_integer(v) or is_float(v) or is_boolean(v) or is_nil(v), do: true
  defp json_safe?(v) when is_atom(v), do: true
  defp json_safe?(v) when is_binary(v), do: String.valid?(v)
  defp json_safe?(v) when is_list(v), do: Enum.all?(v, &json_safe?/1)

  defp json_safe?(%_{} = struct),
    do: struct |> Map.from_struct() |> json_safe?()

  defp json_safe?(v) when is_map(v) do
    Enum.all?(v, fn {k, val} -> json_safe?(k) and json_safe?(val) end)
  end

  defp json_safe?(_), do: false
end
