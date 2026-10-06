# frozen_string_literal: true

Rails.application.config.filter_parameters += %i[
  passw secret token _key crypt salt certificate otp ssn
  relay_secret seed signature code claim_code nonce
]
