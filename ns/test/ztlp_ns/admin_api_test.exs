defmodule ZtlpNs.AdminApiTest do
  use ExUnit.Case, async: true
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
end
