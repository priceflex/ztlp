# frozen_string_literal: true

module Rack
  class Attack
    throttle("auth/ip", limit: 10, period: 60) { |req| req.ip if req.path.start_with?("/auth/", "/claim") && req.post? }
    throttle("api/ip", limit: 10, period: 60) { |req| req.ip if req.path.start_with?("/api/v1/") }
    self.throttled_responder = lambda { |_req|
      [ 429, { "content-type" => "text/plain" }, [ "Too many requests. Slow down.\n" ] ]
    }
  end
end
Rails.application.config.middleware.use Rack::Attack
