# frozen_string_literal: true

class NotificationLog < ApplicationRecord
  belongs_to :notification_channel

  STATUSES = %w[pending sent failed].freeze

  validates :event_type, presence: true
  validates :status, presence: true, inclusion: { in: STATUSES }

  scope :recent, -> { order(created_at: :desc) }
  scope :sent, -> { where(status: "sent") }
  scope :failed, -> { where(status: "failed") }
  scope :pending, -> { where(status: "pending") }

  def mark_sent!
    update!(status: "sent", sent_at: Time.current)
  end

  def mark_failed!(error)
    update!(status: "failed", error_message: error)
  end

  def sent?
    status == "sent"
  end

  def failed?
    status == "failed"
  end

  def pending?
    status == "pending"
  end
end
