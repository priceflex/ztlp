class Deployment < ApplicationRecord
  belongs_to :machine

  validates :status, inclusion: { in: %w[pending running success failed] }
  validates :component, presence: true, inclusion: { in: %w[ns relay gateway] }

  scope :recent, -> { order(created_at: :desc) }
  scope :successful, -> { where(status: "success") }
  scope :failed, -> { where(status: "failed") }

  def duration
    return nil unless started_at
    (finished_at || Time.current) - started_at
  end

  def running?
    status == "running"
  end

  def success?
    status == "success"
  end

  def failed?
    status == "failed"
  end

  def append_log(line)
    self.log = (log || "") + line + "\n"
  end

  def finish!(new_status)
    update!(status: new_status, finished_at: Time.current)
  end
end
