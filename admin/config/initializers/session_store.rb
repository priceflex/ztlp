# frozen_string_literal: true

Rails.application.config.session_store :cookie_store, key: "_ztlp_admin_session",
                                                      same_site: :lax, secure: Rails.env.production? && ENV["FORCE_SSL"] == "true", httponly: true
