# frozen_string_literal: true

# Slice 5b: sweep pending enrollment tokens past expires_at every 5 min.
# Flips them to `expired` (idempotent — pending rows only).
class ExpireEnrollmentsJob < ApplicationJob
  queue_as :default

  def perform
    Enrollment.expire_due!(Time.current)
  end
end
