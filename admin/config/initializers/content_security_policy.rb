# frozen_string_literal: true

# Strict CSP for the directory UI (Slice 1, decision 1 & 2): hand-written JS
# only, no inline scripts, no nonces, nothing external. See
# docs/admin-panel/BUILD_LOOP.md §4 Slice 1.

Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self
    policy.script_src  :self
    policy.style_src   :self
    policy.img_src     :self, :data
    policy.font_src    :self
    policy.connect_src :self
    policy.form_action :self
    policy.frame_ancestors :none
  end
  # No nonce generator: no inline <script> anywhere (CSP 'script-src 'self'' only).
  config.content_security_policy_nonce_generator = nil
end
