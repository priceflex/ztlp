# frozen_string_literal: true

ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"
require "mocha/minitest"

module ActiveSupport
  class TestCase
    parallelize(workers: 1)
    fixtures :all

    def make_admin(role: "super_admin", username: "steve")
      seed, pub = Ztlp::Ed25519.generate
      admin = Admin.create!(username: username, display_name: username.capitalize, pubkey_hex: pub, role: role)
      [ admin, seed ]
    end
  end
end

module ActionDispatch
  class IntegrationTest
    # Full challenge-response login through the real endpoints.
    def sign_in_as(admin, seed)
      post auth_challenge_path, params: { pubkey_hex: admin.pubkey_hex }, as: :json
      nonce = response.parsed_body["nonce"]
      sig = Ztlp::Ed25519.sign(seed_hex: seed, message: Ztlp::Ed25519.login_message(host, nonce))
      post auth_verify_path, params: { pubkey_hex: admin.pubkey_hex, nonce: nonce, signature: sig }, as: :json
      url = response.parsed_body["login_url"]
      get url
      follow_redirect!
    end
  end
end
