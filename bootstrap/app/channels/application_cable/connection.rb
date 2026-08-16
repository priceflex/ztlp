module ApplicationCable
  class Connection < ActionCable::Connection::Base
    identified_by :current_admin

    def connect
      self.current_admin = find_current_admin
      reject_unauthorized_connection unless current_admin
    end

    private

    def find_current_admin
      # Mirror ApplicationController#current_admin so that
      # ActionCable (WebSocket) connections share the same
      # authentication surface — session cookie AND gateway
      # header verification.

      # (1) Session-based login (browser users)
      # [zig-wyxu fix] ActionCable::Connection::Base does not expose a
      # bare `session` method the way ActionController::Base does -
      # this must go through `request.session` (the cookie-jar-backed
      # session available on the connection's underlying Rack request).
      admin_id = request.session[:admin_user_id]
      if admin_id.present?
        admin = AdminUser.find_by(id: admin_id)
        return nil if admin&.locked?
        return admin
      end

      # (2) Gateway header verification (proxy-authenticated)
      trusted_gateway_admin
    end

    def trusted_gateway_admin
      return unless ActiveModel::Type::Boolean.new.cast(ENV["ZTLP_TRUST_GATEWAY_AUTH"])

      secret = ENV["ZTLP_GATEWAY_HEADER_SECRET"].to_s
      return nil if secret.empty?

      status, payload = Ztlp::HeaderVerifier.verify_request(request, secret: secret)
      return nil unless status == :ok

      return unless payload["authenticated"]&.to_s.in?(%w[1 true])

      email = payload["admin-email"].to_s.downcase.strip
      return if email.blank?

      AdminUser.find_by("LOWER(email) = ?", email)
    end
  end
end
