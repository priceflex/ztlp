# frozen_string_literal: true

require "test_helper"

# Unit tests for Ztlp::NsClient (slice 4b). Wire formats pinned to the Elixir NS
# (ns/lib/ztlp_ns, read 2026-10-22):
#   register v2 (server.ex:51): <<0x09, name_len::16, name, type::8, data_len::16, data,
#                                 sig_len::16, sig, pubkey_len::16, pubkey>>
#   canonical signed (registration_auth.ex): <<type::8, name_len::16, name, data_bin>>
#   query (server.ex:171): <<0x01, name_len::16, name, type::8>> padded to 600 bytes
#   query hit (server.ex:185): <<0x02, Record.encode>> where Record.encode (record.ex:196) =
#     <<type::8, name_len::16, name, data_len::32, data, created_at::64, ttl::32, serial::64,
#       sig_len::16, sig, pub_len::16, pub>>  (all big-endian)
#   0x03 not found / 0x04 revoked / 0x06 ack / 0xFF + reason code
#
# The UDP socket is a plain fake (Mocha cannot stub Object#send). Its #recvfrom
# REQUIRES maxlen, like a real UDPSocket.
class NsClientTest < ActiveSupport::TestCase
  AUTHORITY = Ztlp::Ed25519.generate.freeze # [seed_hex, pubkey_hex], test-only

  class FakeSocket
    attr_reader :sent

    # replies: Strings returned in order; an Exception instance is raised instead.
    def initialize(*replies)
      @replies = replies
      @sent = []
    end

    def send(packet, flags)
      raise ArgumentError, "flags" unless flags.is_a?(Integer)

      @sent << packet.b
      packet.bytesize
    end

    def recvfrom(maxlen, *_rest)
      raise ArgumentError, "maxlen must be >= 1500" unless maxlen.is_a?(Integer) && maxlen >= 1500

      r = @replies.shift
      raise r if r.is_a?(Exception)

      [ r.b, [ "AF_INET", 23096, "127.0.0.1", "127.0.0.1" ] ]
    end

    def close; end
  end

  def record_reply(type_byte:, name:, data:, created_at:, ttl:, serial:)
    data_bin = Ztlp::Cbor.encode(data)
    sig = "\x11".b * 64
    pub = "\x22".b * 32
    [ 0x02, type_byte, name.bytesize, name, data_bin.bytesize, data_bin, created_at, ttl, serial,
      sig.bytesize, sig, pub.bytesize, pub ].pack("C C n a* N a* Q> N Q> n a* n a*")
  end

  def reg(sock, data: {}, name: "g.groups.t.ztlp", type: "group")
    Ztlp::NsClient.register("127.0.0.1:1", 5, name: name, type: type, data: data, seed: AUTHORITY[0], socket: sock)
  end

  # ── register ──────────────────────────────────────────────────────

  test "register sends v2 framing over a valid canonical signature; 0x06 is :ok" do
    seed, pub = AUTHORITY
    name = "staff.groups.t.ztlp"
    data = { "members" => [], "description" => "" }
    sock = FakeSocket.new("\x06")
    assert_equal :ok, reg(sock, data: data, name: name)

    pkt = sock.sent.first
    data_bin = Ztlp::Cbor.encode(data)
    assert_equal [ 0x09, name.bytesize ], pkt.unpack("C n")
    assert_equal name, pkt.byteslice(3, name.bytesize)
    off = 3 + name.bytesize
    assert_equal 0x12, pkt.getbyte(off)
    dlen = pkt.byteslice(off + 1, 2).unpack1("n")
    assert_equal data_bin, pkt.byteslice(off + 3, dlen)
    off += 3 + dlen
    assert_equal 64, pkt.byteslice(off, 2).unpack1("n")
    sig = pkt.byteslice(off + 2, 64)
    off += 66
    assert_equal 32, pkt.byteslice(off, 2).unpack1("n")
    assert_equal [ pub ].pack("H*"), pkt.byteslice(off + 2, 32)
    assert_equal off + 34, pkt.bytesize
    canonical = [ 0x12, name.bytesize, name, data_bin ].pack("C n a* a*")
    assert Ztlp::Ed25519.verify(pubkey_hex: pub, message: canonical, signature_hex: sig.unpack1("H*"))
    assert_not_nil seed
  end

  test "register maps 0xFF + code to NsError(code, reason)" do
    err = assert_raises(Ztlp::NsClient::NsError) { reg(FakeSocket.new("\xFF\x05".b)) }
    assert_equal 0x05, err.code
    assert_equal "unauthorized", err.reason
  end

  test "a timeout is retried exactly once, then NsError 0x0C" do
    sock = FakeSocket.new(Errno::EAGAIN.new, Errno::EAGAIN.new, "\x06")
    err = assert_raises(Ztlp::NsClient::NsError) { reg(sock) }
    assert_equal 0x0C, err.code
    assert_equal 2, sock.sent.size
  end

  test "one timeout then an ack succeeds" do
    sock = FakeSocket.new(Errno::EAGAIN.new, "\x06")
    assert_equal :ok, reg(sock)
    assert_equal 2, sock.sent.size
  end

  test "connection refused is NsError 0x0D without retry" do
    sock = FakeSocket.new(Errno::ECONNREFUSED.new)
    err = assert_raises(Ztlp::NsClient::NsError) do
      Ztlp::NsClient.query("127.0.0.1:1", 5, name: "x.t.ztlp", type: "device", socket: sock)
    end
    assert_equal 0x0D, err.code
    assert_equal 1, sock.sent.size
  end

  # ── query ─────────────────────────────────────────────────────────

  test "query pads the 0x01 request to 600 bytes" do
    sock = FakeSocket.new("\x03".b)
    Ztlp::NsClient.query("127.0.0.1:1", 5, name: "d1.t.ztlp", type: "device", socket: sock)
    pkt = sock.sent.first
    assert_equal 600, pkt.bytesize
    assert_equal [ 0x01, 9, "d1.t.ztlp", 0x10 ], pkt.unpack("C n a9 C")
  end

  test "query parses a 0x02 reply in Record.encode format" do
    data = { "node_id" => "ab" * 16, "owner" => "steve.users.t.ztlp", "assurance" => "device-bound" }
    reply = record_reply(type_byte: 0x10, name: "d1.t.ztlp", data: data,
                         created_at: 1_761_100_000, ttl: 86_400, serial: 7)
    rec = Ztlp::NsClient.query("127.0.0.1:1", 5, name: "d1.t.ztlp", type: "device", socket: FakeSocket.new(reply))
    assert_equal({ name: "d1.t.ztlp", type: "device", data: data, created_at: 1_761_100_000,
                   ttl: 86_400, serial: 7 }, rec)
  end

  test "query maps 0x03 to :not_found and 0x04 to :revoked" do
    assert_equal :not_found, Ztlp::NsClient.query("127.0.0.1:1", 5, name: "x.t.ztlp", type: "user",
                                                                     socket: FakeSocket.new("\x03".b))
    assert_equal :revoked, Ztlp::NsClient.query("127.0.0.1:1", 5, name: "x.t.ztlp", type: "user",
                                                                   socket: FakeSocket.new("\x04".b))
  end

  test "a truncated 0x02 reply is NsError 0x0A, not a crash" do
    good = record_reply(type_byte: 0x10, name: "d1.t.ztlp", data: { "a" => 1 }, created_at: 1, ttl: 1, serial: 1)
    err = assert_raises(Ztlp::NsClient::NsError) do
      Ztlp::NsClient.query("127.0.0.1:1", 5, name: "d1.t.ztlp", type: "device",
                                             socket: FakeSocket.new(good.byteslice(0, 20)))
    end
    assert_equal 0x0A, err.code
  end

  # ── list (/admin/records) ─────────────────────────────────────────

  class FakeHttp
    attr_reader :path, :headers

    Resp = Struct.new(:code, :body)

    def initialize(code, body) = @resp = Resp.new(code, body)

    def get(path, headers)
      @path = path
      @headers = headers
      @resp
    end
  end

  test "list signs GET path ts sha256('') with HMAC and parses records" do
    secret = "s" * 32
    body = { "records" => [ { "name" => "staff.groups.t.ztlp", "type" => "group", "data" => { "members" => [] } } ] }
    http = FakeHttp.new("200", JSON.generate(body))
    recs = Ztlp::NsClient.list(9103, secret, type: "group", http: http, ts: 1_761_100_000)
    assert_equal "/admin/records?type=group", http.path
    canon = "GET\n/admin/records?type=group\n1761100000\n#{Digest::SHA256.hexdigest("")}"
    assert_equal OpenSSL::HMAC.hexdigest("SHA256", secret, canon), http.headers["x-ns-signature"]
    assert_equal "1761100000", http.headers["x-ns-timestamp"]
    assert_equal [ { name: "staff.groups.t.ztlp", type: "group", data: { "members" => [] } } ], recs
  end

  test "list maps 401 to NsError 0x05" do
    err = assert_raises(Ztlp::NsClient::NsError) do
      Ztlp::NsClient.list(9103, "s" * 32, type: "group", http: FakeHttp.new("401", "{}"), ts: 1)
    end
    assert_equal 0x05, err.code
  end

  # The NS (ns/lib/ztlp_ns/config.ex) loads ZTLP_NS_ADMIN_API_SECRET as:
  #   32 raw bytes used as-is, OR 64-char hex decoded to 32 bytes.
  # The HMAC key the NS uses is the DECODED 32 raw bytes, not the 64-hex
  # string. admin_headers must mirror that or every /admin/records call
  # against a 64-hex secret returns 401 :bad_signature.
  test "admin_headers HMACs a 64-hex secret with its decoded 32 raw bytes" do
    secret_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    assert_equal 64, secret_hex.bytesize
    secret_raw = [ secret_hex ].pack("H*")
    ts = 1_761_100_000
    path = "/admin/records?type=group"
    canon = "GET\n#{path}\n#{ts}\n#{Digest::SHA256.hexdigest("")}"

    headers = Ztlp::NsClient.admin_headers(secret_hex, ts, path)
    # Keyed on the DECODED raw bytes — the shape the NS verifies.
    assert_equal OpenSSL::HMAC.hexdigest("SHA256", secret_raw, canon), headers["x-ns-signature"]
    # And it is NOT the raw-hex-string key (the pre-fix bug).
    refute_equal OpenSSL::HMAC.hexdigest("SHA256", secret_hex, canon), headers["x-ns-signature"]
  end

  test "admin_headers uses a 32-char non-hex secret as-is (backwards compat)" do
    secret = "s" * 32 # not 64-hex; used verbatim (existing contract)
    ts = 1_761_100_000
    path = "/admin/records"
    canon = "GET\n#{path}\n#{ts}\n#{Digest::SHA256.hexdigest("")}"
    headers = Ztlp::NsClient.admin_headers(secret, ts, path)
    assert_equal OpenSSL::HMAC.hexdigest("SHA256", secret, canon), headers["x-ns-signature"]
  end

  test "reason table: NS codes 0x00..0x0B plus panel-only 0x0C timeout, 0x0D refused" do
    assert_equal (0x00..0x0D).to_a, Ztlp::NsClient::REASON_CODES.keys.sort
    assert_equal "unauthorized", Ztlp::NsClient::REASON_CODES[0x05]
    assert_equal "timeout", Ztlp::NsClient::REASON_CODES[0x0C]
    assert_equal "refused", Ztlp::NsClient::REASON_CODES[0x0D]
  end

  # Prod: the panel container reaches the NS container by name on a shared docker network
  # (ZTLP_NS_ADMIN_BASE_URL=http://ztlp-ns:9103). 127.0.0.1 inside the panel container is the
  # container itself, so the host must come from the setting, not be hard-coded.
  test "the admin API host comes from ZTLP_NS_ADMIN_BASE_URL (default 127.0.0.1)" do
    with_env("ZTLP_NS_ADMIN_BASE_URL" => "http://ztlp-ns:9103") do
      assert_equal "ztlp-ns", Ztlp::NsClient.ns_admin_host
      Net::HTTP.expects(:new).with("ztlp-ns", 9103).returns(FakeHttp.new("200", '{"records":[]}'))
      assert_equal [], Ztlp::NsClient.list(9103, "s" * 32, type: "group", ts: 1)
    end
    with_env("ZTLP_NS_ADMIN_BASE_URL" => nil) { assert_equal "127.0.0.1", Ztlp::NsClient.ns_admin_host }
    with_env("ZTLP_NS_ADMIN_BASE_URL" => "garbage") { assert_equal "127.0.0.1", Ztlp::NsClient.ns_admin_host }
  end

  def with_env(vars)
    old = vars.keys.to_h { |k| [ k, ENV[k] ] }
    vars.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    yield
  ensure
    old.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end
end
