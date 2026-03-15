# frozen_string_literal: true

Rails.application.config.middleware.use OmniAuth::Builder do
  # Google OAuth2 — dynamic config loaded from DB via setup proc
  provider :google_oauth2, setup: ->(env) {
    request = Rack::Request.new(env)
    network_id = request.session[:idp_network_id]
    idp = IdentityProvider.enabled.find_by(network_id: network_id, provider_type: "google_oauth2") if network_id

    if idp
      env["omniauth.strategy"].options[:client_id] = idp.client_id
      env["omniauth.strategy"].options[:client_secret] = idp.client_secret
      env["omniauth.strategy"].options[:hd] = idp.allowed_domain_list.first if idp.allowed_domain_list.any?
    else
      # No IdP configured — will fail gracefully
      env["omniauth.strategy"].options[:client_id] = "not-configured"
      env["omniauth.strategy"].options[:client_secret] = "not-configured"
    end
  }

  # Generic OpenID Connect — dynamic config loaded from DB via setup proc
  provider :openid_connect, setup: ->(env) {
    request = Rack::Request.new(env)
    network_id = request.session[:idp_network_id]
    idp = IdentityProvider.enabled.find_by(network_id: network_id, provider_type: "openid_connect") if network_id

    if idp
      env["omniauth.strategy"].options[:client_options] = {
        identifier: idp.client_id,
        secret: idp.client_secret,
        redirect_uri: "#{request.base_url}/auth/openid_connect/callback"
      }
      env["omniauth.strategy"].options[:issuer] = idp.issuer_url
      env["omniauth.strategy"].options[:discovery] = true
      env["omniauth.strategy"].options[:scope] = [:openid, :email, :profile]
    else
      env["omniauth.strategy"].options[:client_options] = {
        identifier: "not-configured",
        secret: "not-configured"
      }
    end
  }
end

OmniAuth.config.logger = Rails.logger
OmniAuth.config.allowed_request_methods = [:post]
OmniAuth.config.silence_get_warning = true
